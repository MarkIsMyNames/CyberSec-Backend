# config.json — Rationale

## crypto

| Key | Value | Rationale |
|-----|-------|-----------|
| `aead_algorithm` | `AES-256-GCM` | Authenticated encryption with 256-bit key; provides confidentiality and integrity in one pass |
| `nonce_length_bytes` | `12` | 96-bit nonce is the recommended size for AES-GCM; longer nonces reduce the risk of collision under random generation |
| `nonce_strategy` | `counter` | Counter-based nonces guarantee uniqueness; random nonces risk collision after ~2^32 messages under the birthday bound |
| `max_message_bytes` | `10485760` | 10 MiB cap prevents memory exhaustion from oversized payloads |
| `sender_key_rotation` | `on_membership_change` | Signal protocol requirement: sender key must be rotated whenever group membership changes to maintain forward secrecy for new/removed members |
| `hkdf_hash` | `SHA-512` | Used for Double Ratchet and PQXDH key derivation; SHA-512 provides 256-bit security level matching ML-KEM-1024 |
| `ml_kem_variant` | `ML-KEM-1024` | NIST PQC standard (FIPS 203); 1024 variant targets 256-bit post-quantum security level |
| `classical_kem` | `X25519` | Elliptic-curve Diffie-Hellman over Curve25519; fast, constant-time, 128-bit classical security |
| `signature_algorithm` | `Ed25519` | EdDSA over Curve25519; fast, constant-time, deterministic signatures for identity key and prekey authentication |
| `argon2_variant` | `argon2id` | Hybrid of argon2i (side-channel resistance) and argon2d (GPU resistance); recommended by RFC 9106 for password hashing |
| `argon2_time_cost` | `3` | Minimum iterations recommended by RFC 9106 for interactive logins |
| `argon2_memory_cost_kb` | `65536` | 64 MiB; RFC 9106 recommends ≥64 MiB for interactive use |
| `argon2_parallelism` | `4` | Matches typical server core count; higher values increase memory bandwidth requirements for attackers |
| `argon2_hash_len` | `32` | 256-bit output; sufficient for use as a symmetric key or token |
| `database_key_length_bytes` | `32` | 32 bytes = 256-bit key, required by SQLCipher AES-256-CBC full-database encryption |

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
| `max_upload_bytes` | `10485760` | 10 MiB upload cap prevents denial-of-service via large request bodies |
| `tls_min_version` | `TLSv1.3` | TLS 1.3 removes weak cipher suites and legacy negotiation; 1.2 and below are deprecated |
| `db_path` | `securemsg.db` | Relative path resolved from project root; overridden per-environment via config if needed |
| `db_foreign_keys` | `true` | SQLite disables foreign key enforcement by default; must be enabled per-connection via `PRAGMA foreign_keys = ON` |

## logging

| Key | Value | Rationale |
|-----|-------|-----------|
| `log_level` | `DEBUG` | Verbose in development; change to `INFO` or `WARNING` in production |
| `log_max_bytes` | `10485760` | 10 MiB per log file before rotation |
| `log_backup_count` | `5` | Keeps last 5 rotated files (50 MiB total cap) |
