# Username Availability Checker

this tool generates random usernames and checks whether they are available on a specified website. 

## Tested sites

- Instagram: works using 5 letters/characters mode since every 4 letters are taken
- Github: works using 4 letters/characters mode
- Soundcloud: same as github
- Roblox: works using 5 letters/character mode but you need need to configure birthday and passwords


## Features

- Multiple input modes: generate random usernames (letters, alnum, digits, custom pool) or read from a file.
- Concurrent workers: configurable number of parallel checks.
- Rate limiting: global and per‑proxy rate limits with burst support.
- Proxy rotation: round‑robin with automatic dead‑proxy detection.
- Retry logic: exponential backoff with jitter, retry on configurable status codes.
- Flexible availability detection: by HTTP status code, response body substring, or regular expression.
- Multiple output formats: plain, JSON, CSV, NDJSON. Optionally save all results to a separate CSV.
- Resume support: skip already‑checked usernames via a resume file.
- Webhook: POST available usernames to a URL.
- Custom headers & authentication: Basic Auth, Bearer token, custom headers.
- Dry run: generate usernames without making HTTP requests.
- Structured logging: levels (debug, info, warn, error) with optional log file.
- Statistics: periodic and final stats (checks/sec, availability, errors).

## Prerequisites

Go 1.16 or later.

## Installation

Clone this repository or download the `main.go` file. Then build:

```bash
go build -o username-checker main.go
