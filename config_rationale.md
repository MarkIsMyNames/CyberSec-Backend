# config.json — Rationale

## crypto

| Key | Value | Rationale |
|-----|-------|-----------|
| `max_message_bytes` | `102400` | 100 KiB cap, matching Signal's practical ciphertext limit; prevents storage exhaustion and response amplification attacks |
| `nonce_length_bytes` | `12` | 96-bit nonce is the recommended size for AES-GCM; used for TOTP secret encryption |
| `database_key_length_bytes` | `32` | 32 bytes = 256-bit key, required by SQLCipher AES-256-CBC full-database encryption |
| `totp_key_length_bytes` | `32` | 256-bit derived key for AES-256-GCM encryption of TOTP secrets at rest |
| `symmetric_key_length_bytes` | `32` | 256-bit key length used for all symmetric operations on the server |
| `hkdf_info_strings.*` | various | Domain-separation labels for HKDF; each use case gets a unique string to prevent key reuse across contexts |

## messaging

| Key | Value | Rationale |
|-----|-------|-----------|
| `inbox_max_messages` | `50000` | Hard cap per recipient inbox; prevents a malicious sender from exhausting server storage and amplifying read costs for the victim |
| `page_default` | `50` | Default page size for `GET /messages/`; limits response payload without requiring callers to specify a size |
| `page_max` | `100` | Maximum page size clients may request; prevents large single-request data dumps |

## auth

| Key | Value | Rationale |
|-----|-------|-----------|
| `access_token_ttl_minutes` | `15` | Short-lived access tokens limit the window of exposure if a token is stolen |
| `refresh_token_ttl_days` | `7` | Balances user convenience against refresh token compromise risk |
| `preauth_token_ttl_seconds` | `60` | Pre-auth token (issued after password check, before TOTP) expires quickly to prevent TOTP bypass attacks |
| `totp_window` | `1` | Allows ±1 time step (±30 s) to account for clock skew without widening the replay window |
| `jwt_algorithm` | `HS256` | HMAC-SHA256; symmetric signing using `JWT_SECRET_KEY` env var; sufficient for a single-server deployment |

## rate_limits

| Key | Value | Rationale |
|-----|-------|-----------|
| `auth_per_minute` | `10` | Strict limit on login/register to slow credential stuffing and brute-force attacks |
| `messages_per_minute` | `60` | Allows normal messaging activity while preventing spam floods |
| `default_per_minute` | `120` | Permissive default for non-sensitive endpoints |

## server

| Key | Value | Rationale |
|-----|-------|-----------|
| `max_upload_bytes` | `102400` | 100 KiB hard cap at the HTTP layer; matches `max_message_bytes` — no legitimate request body should exceed this |
| `tls_min_version` | `TLSv1.3` | TLS 1.3 removes weak cipher suites and legacy negotiation; 1.2 and below are deprecated |
| `time_for_enforced_http` | `63072000` | 2-year HSTS pin; long enough to cover typical browser cache lifetimes, short enough to recover from a misconfiguration without a multi-year lockout |
| `block_framing` | `DENY` | `X-Frame-Options` value; prevents the app being embedded in any iframe, blocking clickjacking |
| `block_content_sniffing` | `nosniff` | `X-Content-Type-Options` value; stops browsers guessing MIME types, preventing content-sniffing attacks |
| `allowed_content_sources` | `default-src 'none'` | `Content-Security-Policy` value; blocks all resource loading — appropriate for a pure API with no frontend |
| `referrer_exposure` | `no-referrer` | `Referrer-Policy` value; suppresses the `Referer` header on outgoing requests, preventing URL leakage |
| `db_path` | `securemsg.db` | Relative path resolved from project root; overridden per-environment via config if needed |
| `db_foreign_keys` | `true` | SQLite disables foreign key enforcement by default; must be enabled per-connection via `PRAGMA foreign_keys = ON` |

## logging

| Key | Value | Rationale |
|-----|-------|-----------|
| `log_level` | `DEBUG` | Verbose in development; change to `INFO` or `WARNING` in production |
| `log_max_bytes` | `10485760` | 10 MiB per log file before rotation |
| `log_backup_count` | `5` | Keeps last 5 rotated files (50 MiB total cap) |
