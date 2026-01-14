/* Copyright (C) 2026  Henrique Almeida
 * This file is part of tddns.
 *
 * tddns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * tddns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with tddns.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* --- C23 Compatibility --- */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define NODISCARD [[nodiscard]]
#define NULLPTR nullptr
#else
#define NODISCARD __attribute__((warn_unused_result))
#define NULLPTR NULL
#endif

/* --- Constants & Enums --- */

enum
{
	DEFAULT_INTERVAL_SEC = 300, /* 5 minutes */
	MIN_BACKOFF_SEC = 5,
	MAX_BACKOFF_SEC = 3600, /* 1 hour */
	MAX_URL_LEN = 2048,
	MAX_PAYLOAD_LEN = 1024,
	MAX_IP_LEN = 64,
	MAX_ID_LEN = 40, /* Cloudflare IDs are 32 chars */
	MAX_TOKEN_LEN = 256,
	MAX_DOMAIN_LEN = 256,
	HTTP_TIMEOUT_SEC = 20,
	MAX_PATH_LEN = 512
};

typedef enum
{
	IDX_IPV4 = 0,
	IDX_IPV6 = 1,
	IDX_COUNT = 2
} RecordIndex;

typedef enum
{
	REC_A = (1 << IDX_IPV4),
	REC_AAAA = (1 << IDX_IPV6),
	REC_BOTH = (REC_A | REC_AAAA)
} RecordType;

/* Runtime path buffers */
static char g_pid_file[MAX_PATH_LEN];
static char g_state_file[MAX_PATH_LEN];

/* APIs */
static const char *const API_CF_BASE = "https://api.cloudflare.com/client/v4";
static const char *const API_IP_PROVIDERS[IDX_COUNT] = {
	"https://api.ipify.org", "https://api6.ipify.org"};
static const char *const REC_NAME_STR[IDX_COUNT] = {"A", "AAAA"};

/* --- Types --- */

typedef struct
{
	char token[MAX_TOKEN_LEN];
	char domain[MAX_DOMAIN_LEN];
	RecordType mode;
	int interval;
} Config;

typedef struct
{
	char id[MAX_ID_LEN];
	char ip[MAX_IP_LEN];
	bool active;
	bool resolved;
	bool needs_update;
} RecordState;

typedef struct
{
	char zone_id[MAX_ID_LEN];
	RecordState records[IDX_COUNT];
} CloudflareState;

typedef struct
{
	char *data;
	size_t size;
} MemoryStruct;

typedef enum
{
	STATE_INIT,
	STATE_RESOLVE_ZONE,
	STATE_RESOLVE_RECORD,
	STATE_CHECK_IP,
	STATE_UPDATE_DNS,
	STATE_IDLE,
	STATE_ERROR
} AppState;

typedef enum
{
	HTTP_GET,
	HTTP_PATCH
} HttpMethod;

typedef enum
{
	LOG_INFO,
	LOG_WARN,
	LOG_ERROR,
	LOG_FATAL
} LogLevel;

/* --- Globals --- */

static volatile sig_atomic_t g_running = 1;

/* --- Helper Prototypes --- */

/* System & Utils */
static void handle_signal(int sig);
static void log_msg(LogLevel level, const char *fmt, ...);
static void sleep_interruptible(int seconds);
NODISCARD static bool write_pid_file(void);
NODISCARD static FILE *fopen_tddns(const char *path, const char *mode);
static void setup_runtime_paths(void);

/* State Persistence */
static void load_state_ips(CloudflareState *state);
NODISCARD static bool save_state_ips(const CloudflareState *state);

/* Networking */
static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp);
NODISCARD static bool perform_http_request(const char *url, HttpMethod method,
										   const char *token,
										   const char *json_payload,
										   MemoryStruct *resp);

/* Logic & Parsing */
NODISCARD static bool extract_json_value(const char *json, const char *key,
										 char *dest, size_t dest_len);
NODISCARD static bool get_public_ip(RecordIndex idx, char *ip_buf);
NODISCARD static bool resolve_zone_id(const Config *cfg,
									  CloudflareState *state);
NODISCARD static bool
resolve_record_id(const Config *cfg, CloudflareState *state, RecordIndex idx);
NODISCARD static bool update_cf_record(const Config *cfg,
									   const CloudflareState *state,
									   RecordIndex idx);

/* State Handlers */
static AppState handle_resolve_zone_state(const Config *cfg,
										  CloudflareState *state, int *backoff);
static AppState handle_resolve_record_state(const Config *cfg,
											CloudflareState *state,
											int *backoff);
static AppState handle_check_ip_state(CloudflareState *state, int *backoff);
static AppState handle_update_dns_state(const Config *cfg,
										CloudflareState *state, int *backoff);
static AppState handle_idle_state(const Config *cfg);
static AppState handle_error_state(const CloudflareState *state, int *backoff);
static AppState process_state(const Config *cfg, CloudflareState *state,
							  AppState current, int *backoff);

/* --- Implementation --- */

static void handle_signal(int sig)
{
	(void)sig;
	g_running = 0;
}

static void log_msg(LogLevel level, const char *fmt, ...)
{
	time_t now = time(NULL);
	struct tm tm_info;
	char time_buf[26];
	const char *level_str;
	FILE *stream = stdout;

	localtime_r(&now, &tm_info);
	strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_info);

	switch (level)
	{
	case LOG_INFO:
		level_str = "INFO";
		break;
	case LOG_WARN:
		level_str = "WARN";
		stream = stderr;
		break;
	case LOG_ERROR:
		level_str = "ERROR";
		stream = stderr;
		break;
	case LOG_FATAL:
		level_str = "FATAL";
		stream = stderr;
		break;
	default:
		level_str = "UNKNOWN";
		break;
	}

	fprintf(stream, "[%s] [%s] ", time_buf, level_str);

	va_list args;
	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	va_end(args);

	fprintf(stream, "\n");
	fflush(stream);
}

static void sleep_interruptible(int seconds)
{
	if (seconds <= 0)
	{
		return;
	}
	struct timespec req = {.tv_sec = seconds, .tv_nsec = 0};
	struct timespec rem = {0};

	/* Loop until sleep completes or signal interrupts */
	while (g_running && nanosleep(&req, &rem) == -1)
	{
		if (errno == EINTR)
		{
			req = rem;
		}
		else
		{
			break;
		}
	}
}

NODISCARD static FILE *fopen_tddns(const char *path, const char *mode)
{
	if (strcmp(mode, "w") != 0)
	{
		return fopen(path, mode);
	}
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		return NULL;
	}
	FILE *f = fdopen(fd, "w");
	if (!f)
	{
		close(fd);
	}
	return f;
}

static void setup_runtime_paths(void)
{
	uid_t uid = getuid();
	const char *runtime_dir = "/var/run";

	/* Check if running in Docker container */
	bool in_docker = (access("/.dockerenv", F_OK) == 0);

	if (!in_docker && uid != 0)
	{
		runtime_dir = getenv("XDG_RUNTIME_DIR");
		if (runtime_dir == NULL)
		{
			runtime_dir = "/tmp";
		}
	}
	snprintf(g_pid_file, sizeof(g_pid_file), "%s/ddns.pid", runtime_dir);
	snprintf(g_state_file, sizeof(g_state_file), "%s/ddns.state",
			 runtime_dir);
}

NODISCARD static bool write_pid_file(void)
{
	FILE *f = fopen_tddns(g_pid_file, "w");
	if (!f)
	{
		return false;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return true;
}

/* --- Persistence --- */

static void load_state_ips(CloudflareState *state)
{
	FILE *f = fopen(g_state_file, "r");
	if (!f)
	{
		return;
	}

	char line[MAX_IP_LEN + 16];
	while (fgets(line, sizeof(line), f))
	{
		for (int idx = 0; idx < IDX_COUNT; idx++)
		{
			size_t nlen = strlen(REC_NAME_STR[idx]);
			size_t line_len = strlen(line);
			if (line_len <= nlen ||
				strncmp(line, REC_NAME_STR[idx], nlen) != 0 ||
				!isspace((unsigned char)line[nlen]))
			{
				continue;
			}

			char *val = strchr(line, ' ');
			if (!val)
			{
				continue;
			}

			val++; /* Skip the space */
			size_t slen = strlen(val);
			if (slen > 0 && val[slen - 1] == '\n')
			{
				val[slen - 1] = '\0';
			}
			snprintf(state->records[idx].ip, MAX_IP_LEN, "%s", val);
			log_msg(LOG_INFO, "Loaded %s IP from state: %s",
					REC_NAME_STR[idx], val);
		}
	}
	fclose(f);
}

NODISCARD static bool save_state_ips(const CloudflareState *state)
{
	char tmp_path[MAX_PATH_LEN + 8];
	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_state_file);

	FILE *f = fopen_tddns(tmp_path, "w");
	if (!f)
	{
		return false;
	}

	for (int idx = 0; idx < IDX_COUNT; idx++)
	{
		if (state->records[idx].active && state->records[idx].ip[0])
		{
			if (fprintf(f, "%s %s\n", REC_NAME_STR[idx],
						state->records[idx].ip) < 0)
			{
				fclose(f);
				unlink(tmp_path);
				return false;
			}
		}
	}

	/* Ensure data is on disk */
	if (fflush(f) != 0)
	{
		fclose(f);
		unlink(tmp_path);
		return false;
	}
	int fd = fileno(f);
	if (fd != -1)
	{
		fsync(fd);
	}

	fclose(f);

	/* Atomic swap */
	if (rename(tmp_path, g_state_file) != 0)
	{
		unlink(tmp_path);
		return false;
	}
	log_msg(LOG_INFO, "State saved successfully.");
	return true;
}

/* --- Networking --- */

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	MemoryStruct *mem = (MemoryStruct *)userp;

	char *ptr = realloc(mem->data, mem->size + realsize + 1);
	if (!ptr)
	{
		log_msg(LOG_ERROR, "Out of memory in curl callback");
		return 0; /* Causes libcurl to abort transfer */
	}

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

NODISCARD static bool perform_http_request(const char *url, HttpMethod method,
										   const char *token,
										   const char *json_payload,
										   MemoryStruct *resp)
{
	CURL *curl = curl_easy_init();
	if (!curl)
	{
		return false;
	}

	struct curl_slist *headers = NULL;
	if (token)
	{
		char auth_header[MAX_TOKEN_LEN + 32];
		snprintf(auth_header, sizeof(auth_header),
				 "Authorization: Bearer %s", token);
		headers = curl_slist_append(headers, auth_header);
		headers = curl_slist_append(headers,
									"Content-Type: application/json");
	}

	resp->data = malloc(1);
	if (!resp->data)
	{
		if (headers)
		{
			curl_slist_free_all(headers);
		}
		curl_easy_cleanup(curl);
		return false;
	}
	resp->data[0] = '\0';
	resp->size = 0;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)HTTP_TIMEOUT_SEC);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "tddns/1.0");

	if (method == HTTP_PATCH)
	{
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
		if (json_payload)
		{
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
							 json_payload);
		}
	}

	CURLcode res = curl_easy_perform(curl);
	long http_code = 0;
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	bool success = (res == CURLE_OK && http_code >= 200 && http_code < 300);

	if (!success)
	{
		log_msg(LOG_WARN, "HTTP Request failed: %s (Code: %ld) URL: %s",
				curl_easy_strerror(res), http_code, url);
		if (resp->data)
		{
			log_msg(LOG_WARN, "Response: %.100s...", resp->data);
		}
		free(resp->data);
		resp->data = NULL;
		resp->size = 0;
	}

	if (headers)
	{
		curl_slist_free_all(headers);
	}
	curl_easy_cleanup(curl);
	return success;
}

/* --- Logic & Parsing --- */

NODISCARD static bool extract_json_value(const char *json, const char *key,
										 char *dest, size_t dest_len)
{
	if (!json || !key || !dest)
	{
		return false;
	}

	/* Construct search pattern: "key": */
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\":", key);

	const char *start = strstr(json, pattern);
	if (!start)
	{
		return false;
	}

	start += strlen(pattern);

	/* Skip whitespace */
	while (*start && isspace((unsigned char)*start))
	{
		start++;
	}

	if (*start != '\"')
	{
		return false; /* Expect string value */
	}
	start++; /* Skip opening quote */

	const char *end = strchr(start, '\"');
	if (!end)
	{
		return false;
	}

	size_t val_len = (size_t)(end - start);
	if (val_len >= dest_len)
	{
		return false;
	}

	memcpy(dest, start, val_len);
	dest[val_len] = '\0';
	return true;
}

NODISCARD static bool get_public_ip(RecordIndex idx, char *ip_buf)
{
	MemoryStruct resp = {NULL, 0};
	const char *url = API_IP_PROVIDERS[idx];

	if (!perform_http_request(url, HTTP_GET, NULL, NULL, &resp))
	{
		return false;
	}

	if (resp.size >= MAX_IP_LEN || resp.size == 0)
	{
		log_msg(LOG_ERROR, "Invalid IP length received for %s",
				REC_NAME_STR[idx]);
		free(resp.data);
		return false;
	}

	/* Simple trim of whitespace */
	char *start = resp.data;
	while (*start && isspace((unsigned char)*start))
	{
		start++;
	}
	char *end = start + strlen(start) - 1;
	while (end > start && isspace((unsigned char)*end))
	{
		*end-- = '\0';
	}

	if (strlen(start) >= MAX_IP_LEN)
	{
		free(resp.data);
		return false;
	}

	strcpy(ip_buf, start);
	free(resp.data);
	return true;
}

NODISCARD static bool resolve_zone_id(const Config *cfg,
									  CloudflareState *state)
{
	MemoryStruct resp = {NULL, 0};
	char url[MAX_URL_LEN];
	char search_domain[MAX_DOMAIN_LEN];
	bool zone_found = false;

	/* Start with the full domain provided by the user */
	snprintf(search_domain, sizeof(search_domain), "%s", cfg->domain);

	while (!zone_found)
	{
		snprintf(url, sizeof(url), "%s/zones?name=%s&status=active",
				 API_CF_BASE, search_domain);
		log_msg(LOG_INFO, "Resolving Zone ID for %s...", search_domain);

		if (!perform_http_request(url, HTTP_GET, cfg->token, NULL,
								  &resp))
		{
			return false; /* HTTP request failed */
		}

		if (extract_json_value(resp.data, "id", state->zone_id,
							   sizeof(state->zone_id)))
		{
			zone_found = true;
			log_msg(LOG_INFO, "Found Zone ID: %s", state->zone_id);
		}
		else
		{
			/* Zone not found, try stripping the first subdomain */
			char *dot = strchr(search_domain, '.');
			if (dot && dot[1])
			{
				/* Move the string pointer forward */
				char *next_domain = dot + 1;
				memmove(search_domain, next_domain,
						strlen(next_domain) + 1);
				log_msg(LOG_INFO,
						"Zone not found, trying parent: %s",
						search_domain);
			}
			else
			{
				/* No more parents to try */
				log_msg(LOG_ERROR,
						"Could not find Zone ID for %s or its "
						"parents.",
						cfg->domain);
				free(resp.data);
				return false;
			}
		}
		free(resp.data);
		resp.data = NULL;
	}
	return true;
}

NODISCARD static bool
resolve_record_id(const Config *cfg, CloudflareState *state, RecordIndex idx)
{
	MemoryStruct resp = {NULL, 0};
	char url[MAX_URL_LEN];

	snprintf(url, sizeof(url), "%s/zones/%s/dns_records?name=%s&type=%s",
			 API_CF_BASE, state->zone_id, cfg->domain, REC_NAME_STR[idx]);

	log_msg(LOG_INFO, "Resolving Record ID for %s (%s)...", cfg->domain,
			REC_NAME_STR[idx]);

	if (!perform_http_request(url, HTTP_GET, cfg->token, NULL, &resp))
	{
		return false;
	}

	if (!extract_json_value(resp.data, "id", state->records[idx].id,
							sizeof(state->records[idx].id)))
	{
		log_msg(
			LOG_ERROR,
			"Failed to extract Record ID for %s (%s). Does the record "
			"exist?",
			cfg->domain, REC_NAME_STR[idx]);
		free(resp.data);
		return false;
	}

	log_msg(LOG_INFO, "Found Record ID for %s: %s", REC_NAME_STR[idx],
			state->records[idx].id);
	free(resp.data);
	state->records[idx].resolved = true;
	return true;
}

NODISCARD static bool update_cf_record(const Config *cfg,
									   const CloudflareState *state,
									   RecordIndex idx)
{
	char url[MAX_URL_LEN];
	char payload[MAX_PAYLOAD_LEN];
	MemoryStruct resp = {NULL, 0};

	snprintf(url, sizeof(url), "%s/zones/%s/dns_records/%s", API_CF_BASE,
			 state->zone_id, state->records[idx].id);

	/* Using PATCH to update only content */
	snprintf(payload, sizeof(payload), "{\"content\":\"%s\"}",
			 state->records[idx].ip);

	log_msg(LOG_INFO, "Updating %s DNS record to %s...", REC_NAME_STR[idx],
			state->records[idx].ip);
	if (!perform_http_request(url, HTTP_PATCH, cfg->token, payload,
							  &resp))
	{
		return false;
	}

	log_msg(LOG_INFO, "%s record updated successfully.", REC_NAME_STR[idx]);
	free(resp.data);
	return true;
}

static AppState handle_resolve_zone_state(const Config *cfg,
										  CloudflareState *state,
										  int *backoff)
{
	if (resolve_zone_id(cfg, state))
	{
		*backoff = MIN_BACKOFF_SEC;
		return STATE_RESOLVE_RECORD;
	}
	return STATE_ERROR;
}

static AppState handle_resolve_record_state(const Config *cfg,
											CloudflareState *state,
											int *backoff)
{
	for (int idx = 0; idx < IDX_COUNT; idx++)
	{
		if (state->records[idx].active &&
			!state->records[idx].resolved &&
			!resolve_record_id(cfg, state, (RecordIndex)idx))
		{
			return STATE_ERROR;
		}
	}
	*backoff = MIN_BACKOFF_SEC;
	return STATE_CHECK_IP;
}

static AppState handle_check_ip_state(CloudflareState *state, int *backoff)
{
	bool any_changed = false;
	for (int idx = 0; idx < IDX_COUNT; idx++)
	{
		if (!state->records[idx].active)
		{
			continue;
		}
		char detected[MAX_IP_LEN] = {0};
		if (!get_public_ip((RecordIndex)idx, detected))
		{
			log_msg(LOG_WARN, "Failed to check public IP for %s.",
					REC_NAME_STR[idx]);
			return STATE_ERROR;
		}
		if (strcmp(detected, state->records[idx].ip) != 0)
		{
			log_msg(LOG_INFO, "%s IP changed: %s -> %s",
					REC_NAME_STR[idx],
					state->records[idx].ip[0]
						? state->records[idx].ip
						: "(none)",
					detected);
			snprintf(state->records[idx].ip, MAX_IP_LEN, "%s",
					 detected);
			state->records[idx].needs_update = true;
			any_changed = true;
		}
		else
		{
			log_msg(LOG_INFO, "%s IP unchanged: %s",
					REC_NAME_STR[idx], detected);
		}
	}
	*backoff = MIN_BACKOFF_SEC;
	if (!any_changed)
	{
		log_msg(LOG_INFO,
				"No IP changes detected. Entering idle state.");
	}
	return (any_changed) ? STATE_UPDATE_DNS : STATE_IDLE;
}

static AppState handle_update_dns_state(const Config *cfg,
										CloudflareState *state, int *backoff)
{
	for (int idx = 0; idx < IDX_COUNT; idx++)
	{
		if (state->records[idx].active &&
			state->records[idx].needs_update)
		{
			if (!update_cf_record(cfg, state, (RecordIndex)idx))
			{
				log_msg(LOG_ERROR,
						"Failed to update %s record.",
						REC_NAME_STR[idx]);
				return STATE_ERROR;
			}
			state->records[idx].needs_update = false;
		}
	}
	log_msg(LOG_INFO, "DNS synchronization successful.");
	if (!save_state_ips(state))
	{
		log_msg(LOG_WARN, "Failed to save state to disk.");
	}
	*backoff = MIN_BACKOFF_SEC;
	return STATE_IDLE;
}

static AppState handle_idle_state(const Config *cfg)
{
	log_msg(LOG_INFO, "Waiting %d seconds until next check...",
			cfg->interval);
	sleep_interruptible(cfg->interval);
	return STATE_CHECK_IP;
}

static AppState handle_error_state(const CloudflareState *state, int *backoff)
{
	log_msg(LOG_INFO, "Retrying in %d seconds...", *backoff);
	sleep_interruptible(*backoff);
	*backoff =
		(*backoff * 2 > MAX_BACKOFF_SEC) ? MAX_BACKOFF_SEC : *backoff * 2;
	if (state->zone_id[0] == 0)
	{
		return STATE_RESOLVE_ZONE;
	}
	/* Check if any active records need resolution */
	for (int idx = 0; idx < IDX_COUNT; idx++)
	{
		if (state->records[idx].active &&
			!state->records[idx].resolved)
		{
			return STATE_RESOLVE_RECORD;
		}
	}
	return STATE_CHECK_IP;
}

static AppState process_state(const Config *cfg, CloudflareState *state,
							  AppState current, int *backoff)
{
	switch (current)
	{
	case STATE_INIT:
		return STATE_RESOLVE_ZONE;
	case STATE_RESOLVE_ZONE:
		return handle_resolve_zone_state(cfg, state, backoff);
	case STATE_RESOLVE_RECORD:
		return handle_resolve_record_state(cfg, state, backoff);
	case STATE_CHECK_IP:
		return handle_check_ip_state(state, backoff);
	case STATE_UPDATE_DNS:
		return handle_update_dns_state(cfg, state, backoff);
	case STATE_IDLE:
		return handle_idle_state(cfg);
	case STATE_ERROR:
		return handle_error_state(state, backoff);
	default:
		return STATE_ERROR;
	}
}

int main(void)
{
	/* Global Init */
	if (curl_global_init(CURL_GLOBAL_ALL) != 0)
	{
		fprintf(stderr, "FATAL: Failed to init curl\n");
		return EXIT_FAILURE;
	}

	setup_runtime_paths();

	struct sigaction sa = {0};
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Configuration */
	Config cfg = {0};
	const char *env_token = getenv("CF_TOKEN");
	const char *env_domain = getenv("DOMAIN");
	const char *env_type = getenv("RECORD_TYPE");
	const char *env_int = getenv("INTERVAL");

	if (!env_token || !env_domain)
	{
		fprintf(stderr, "FATAL: CF_TOKEN and DOMAIN are required.\n");
		curl_global_cleanup();
		return EXIT_FAILURE;
	}

	snprintf(cfg.token, sizeof(cfg.token), "%s", env_token);
	snprintf(cfg.domain, sizeof(cfg.domain), "%s", env_domain);
	cfg.interval = (env_int) ? atoi(env_int) : DEFAULT_INTERVAL_SEC;
	cfg.interval =
		(cfg.interval <= 0) ? DEFAULT_INTERVAL_SEC : cfg.interval;

	/* Setup Active Records based on config */
	CloudflareState state = {0};
	if (env_type && strcmp(env_type, "AAAA") == 0)
	{
		cfg.mode = REC_AAAA;
		state.records[IDX_IPV6].active = true;
	}
	else if (env_type && strcmp(env_type, "BOTH") == 0)
	{
		cfg.mode = REC_BOTH;
		state.records[IDX_IPV4].active = true;
		state.records[IDX_IPV6].active = true;
	}
	else
	{
		cfg.mode = REC_A;
		state.records[IDX_IPV4].active = true;
	}

	if (!write_pid_file())
	{
		perror("Failed to write PID file"); /* Non-fatal */
	}

	log_msg(LOG_INFO, "tddns started. Domain: %s, Mode: %s, Interval: %ds",
			cfg.domain,
			(cfg.mode == REC_BOTH) ? "BOTH"
								   : (cfg.mode == REC_A ? "A" : "AAAA"),
			cfg.interval);

	/* State Setup */
	load_state_ips(&state);

	AppState current_state = STATE_INIT;
	int backoff_timer = MIN_BACKOFF_SEC;

	/* Event Loop */
	while (g_running)
	{
		current_state =
			process_state(&cfg, &state, current_state, &backoff_timer);
	}

	log_msg(LOG_INFO, "Shutting down...");
	unlink(g_pid_file);
	curl_global_cleanup();
	return EXIT_SUCCESS;
}
