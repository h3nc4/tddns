# tddns

`tddns` is a Tiny DDNS daemon for Cloudflare.

## Overview

`tddns` periodically checks the public IPv4 and/or IPv6 address of the host it is running on. If the address has changed since the last check, it updates the corresponding DNS record in Cloudflare via their API and persists the last known IP addresses in local state files to avoid unnecessary API calls.

If any network errors occur, the daemon waits and retries, gradually increasing the wait time to avoid API rate limits.

## Configuration

`tddns` reads its configuration from environment variables.

| Variable      | Default | Description                                        |
| ------------- | ------- | -------------------------------------------------- |
| `CF_TOKEN`    | (none)  | **Required**. Your Cloudflare API Token.           |
| `DOMAIN`      | (none)  | **Required**. The full FQDN to update              |
| `RECORD_TYPE` | `A`     | `A` for IPv4, `AAAA` for IPv6, or `BOTH`.          |
| `INTERVAL`    | `300`   | Time in seconds between checks. Defaults to 5 min. |

### Creating a Cloudflare Token

To use `tddns`, create a scoped API token with the following steps:

```none
In Cloudflare dashboard, go to  Profile -> API Tokens -> Create Token -> Create Custom Token
Permissions:
  Zone    Read
  DNS     Edit

Zone Resources:
Include -> Specific zone -> mydomain.com
```

## Usage

### Docker

The container is built from scratch and contains only the static binary and SSL certificates.

Use network mode `host` to enable IPv6 support.

```console
docker run -d \
  --network host \
  -e CF_TOKEN="your_token_here" \
  -e DOMAIN="sub.example.com" \
  -e RECORD_TYPE="BOTH" \
  h3nc4/tddns
```

### Native

If you prefer running natively, follow these steps:

```console
export CF_TOKEN="your_token_here"
export DOMAIN="sub.example.com"
export RECORD_TYPE="BOTH"
./tddns
```

`tddns` attempts to write state files to `/var/run/`. If running as a non-root user locally, ensure the user has write permissions to the working directory or modify the source paths.

## Development

To start developing `tddns`, install libcurl4-openssl-dev and build with `make`.

## License

tddns is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tddns is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tddns. If not, see <https://www.gnu.org/licenses/>.
