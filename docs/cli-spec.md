# `site` CLI — Specification (Phase 1 draft)

Installed at `/usr/local/bin/site`. It's a thin `#!/usr/bin/python3 -I` wrapper that imports `/usr/lib/ozenix`. The interface is inspired by Webinoly's site commands, but this is an independent implementation.

## 1. Grammar

```text
site [GLOBAL-FLAGS] <target> <verb> [<sub-verb>] [ARGS] [FLAGS]

target := <domain> | list | system | help | version
```

- A `<domain>` must contain a dot. It's normalized to IDNA A-labels and lowercased. `list`, `system`, `help`, and `version` are reserved words and can never be domains.
- Unknown verbs fail with exit code 2 and a "did you mean" hint. The CLI never guesses an action.

## 2. Global flags

| Flag | Meaning |
|---|---|
| `--help`, `-h` | Help for the current level (`site example.com ssl --help`) |
| `--json` | Machine-readable output on stdout. Logs go to stderr. Stable schema with a `schema_version` field. |
| `--dry-run` | Print the full plan (steps, files, diffs). Change nothing. Supported by **every** mutating command. |
| `--confirm <domain>` | Non-interactive confirmation for destructive commands. Must exactly match the target. |
| `--yes` | Accepted **only** for non-destructive prompts. Never satisfies a destructive confirmation. |
| `--verbose`, `-v` / `--quiet`, `-q` | Output detail |
| `--no-color` | Also implied when stdout isn't a TTY |

## 3. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Operation failed (rolled back where possible; details in the message and audit log) |
| 2 | Usage error |
| 3 | Validation error (bad domain, version, name) |
| 4 | Lock busy (another operation is in progress) |
| 5 | Precondition not met (e.g. DNS doesn't point here, so SSL isn't eligible) |
| 6 | Confirmation refused or missing |
| 10 | Audit completed with warnings |
| 11 | Audit completed with critical findings |

## 4. Commands

Legend: **D** = destructive (needs typed confirmation), **R** = read-only, **M** = mutating (supports `--dry-run`).

### Sites
| Command | Kind | Notes |
|---|---|---|
| `site <d> create [--type php\|static\|proxy] [--php 8.3] [--tier s\|c] [--writable-code] [--no-ssl] [--alias <d2>…]` | M | Default type `php`, tier `s`. AutoSSL is attempted once DNS is eligible. |
| `site <d> create --type proxy --upstream unix:<tenant-socket>\|https://<host>` | M | Upstreams on loopback or private ranges are **rejected** (SSRF/lateral-movement guard). |
| `site <d> status` | R | Config, runtime, TLS, DB, resource use, last backup |
| `site <d> enable` / `disable` | M | `disable` serves a 503 maintenance page and stops the runtime. Data is untouched. |
| `site <d> delete [--purge]` | D | Without `--purge`: tenant archived and runtime removed, data retained 30 days. `--purge` erases data, DB, and backups (backups only with an extra confirmation). |
| `site <d> repair` | M | Finish or roll back an interrupted operation from the journal |
| `site <d> logs [--access\|--error\|--php] [--follow]` | R | |
| `site list [--json]` | R | |

### SSL
| Command | Kind |
|---|---|
| `site <d> ssl` (issue now) / `site <d> autossl [on\|off]` | M |
| `site <d> ssl status` | R |
| `site <d> ssl renew [--force]` | M (`--force` honours rate-limit guard) |
| `site <d> ssl revoke` | D |
| Options: `--challenge http\|dns`, `--staging` | |

### PHP
`php status` (R) · `php <version>` (M; version from the installed allowlist; pool is rebuilt and validated, previous version kept for rollback) · `php restart` (M) · `php optimize [--dry-run]` (M)

### Optimization
`site <d> optimize [--analyze\|--dry-run]` · `site system optimize [--analyze\|--dry-run\|--apply\|--profile small\|medium\|large\|dedicated\|high-traffic\|--rollback <id>\|--history]`. Without `--apply`, `system optimize` only analyzes.

### Database
`db create [--name <n>]` (M) · `db status` (R) · `db backup` (M) · `db restore [--snapshot <id>]` (D) · `db credentials [--rotate]` (M; prints only to a TTY, never in `--json` unless `--show-secret`)

### SFTP
`sftp create [--key <file>\|--key-stdin] [--name <suffix>]` (M; key-only) · `sftp list` (R) · `sftp revoke <username>` (D)

### Security and isolation
`site <d> security` (R) · `site <d> isolation status` (R) · `site <d> isolation audit` (R) · `site <d> isolation test` (R; runs active probes from *inside* the tenant sandbox, never touches other tenants' data)

### Backups
`site <d> backup` (M) · `site <d> backup list` (R) · `site <d> restore [--snapshot <id>] [--files\|--db\|--all] [--to-staging]` (D) · `site system backup [--verify\|--test-restore]` (M)

### Cloudflare
`site <d> cloudflare status|dns|ssl|security` are **read-only by default** and show findings plus a proposed diff. `--apply` makes changes, after a diff preview and confirmation.

### System
`system status` (R) · `system health` (R; includes reboot-required) · `system update --check` (R) · `system update --security` (M) · `system update` (M; non-major only) · `system backup` (M) · `system logs [--audit]` (R) · `system security` (R) · `system audit` (R) · `system firewall status|confirm|rollback` (M)

## 5. Output contract

- Text mode: one summary line per step (`✔ created user t0001`), then a final result line. Warnings go to stderr.
- JSON mode: `{"schema_version":1,"ok":bool,"command":[...],"result":{...},"warnings":[...],"errors":[{"code":"...","message":"..."}]}`.
- Audit/security reports always include `"disclaimer": "Automated checks passed for the listed controls only. This is not a guarantee of security."`

## 6. Confirmation UX for destructive commands

```text
$ sudo site example.com delete --purge
This will PERMANENTLY delete: tenant t0004, 2.1 GB files, database t0004_app, 14 backup snapshots.
Type the domain name to confirm: example.com
```
