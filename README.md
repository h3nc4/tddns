# tddns

`tddns` is a Tiny DDNS daemon for Cloudflare.

## Run with Docker

The container is built from scratch and holds the static binary plus a CA bundle, nothing else.

`--network host` is what lets the daemon see the host's own addresses. On a bridge network it would read the container's address instead and publish that to DNS.

```console
docker run -d \
  --network host \
  -e CF_TOKEN="your_token_here" \
  -e DOMAIN="sub.example.com" \
  -e RECORD_TYPE="BOTH" \
  h3nc4/tddns
```

`CF_TOKEN` and `DOMAIN` are both required and neither has a default. `CF_TOKEN` is the one that needs creating, and [Cloudflare token](#cloudflare-token) covers the permissions to give it. [Environment variables](#environment-variables) covers the rest.

## Cloudflare token

`tddns` needs a scoped API token, created with the following steps.

```none
In Cloudflare dashboard, go to  Profile -> API Tokens -> Create Token -> Create Custom Token
Permissions:
  Zone    Read
  DNS     Edit

Zone Resources:
Include -> Specific zone -> mydomain.com
```

## Environment variables

`tddns` reads its configuration from environment variables.

| Variable      | Default | Description                                        |
| ------------- | ------- | -------------------------------------------------- |
| `CF_TOKEN`    | (none)  | **Required**. Your Cloudflare API Token.           |
| `DOMAIN`      | (none)  | **Required**. The full FQDN to update              |
| `RECORD_TYPE` | `A`     | `A` for IPv4, `AAAA` for IPv6, or `BOTH`.          |
| `INTERVAL`    | `300`   | Time in seconds between checks. Defaults to 5 min. |

## Running natively

```console
export CF_TOKEN="your_token_here"
export DOMAIN="sub.example.com"
export RECORD_TYPE="BOTH"
./tddns
```

`tddns` writes `ddns.pid` and `ddns.state` into a runtime directory it picks for itself. Inside a container, or as root, that is `/var/run`. Run by an ordinary user on a host, it uses `XDG_RUNTIME_DIR` and falls back to `/tmp`, so no path needs preparing by hand.

## How it works

`tddns` periodically checks the public IPv4 and/or IPv6 address of the host it is running on. If the address has changed since the last check, it updates the corresponding DNS record in Cloudflare via their API and persists the last known IP addresses in local state files to avoid unnecessary API calls.

A network error puts the daemon into a retry that doubles its wait, from 5 seconds up to a ceiling of one hour, which keeps a long outage from spending the Cloudflare rate limit.

The address itself comes from `api.ipify.org` over IPv4 and `api6.ipify.org` over IPv6.

## Development

`tddns` is one C file against libcurl. On Debian and Devuan the header package is `libcurl4-openssl-dev`, then `make`.

## License

<!-- vale off -->

tddns is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tddns is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tddns. If not, see <https://www.gnu.org/licenses/>.
