# config.json — Rationale

## crypto

| Key                            | Value                     | Rationale                                                                                                                                                                                          |
|--------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `max_message_bytes`            | `102400`                  | DoS protection — 100 KiB cap, matching Signal's ciphertext limit; an uncapped upload would allow an attacker to exhaust server memory with a single request.                                       |
| `nonce_length_bytes`           | `12`                      | NIST SP 800-38D §8.2 specifies 96-bit as the only IV length that avoids internal hashing in GCM; other lengths waste entropy and create birthday-paradox collision risk in the authentication tag. |
| `encryption_key_length_bytes`  | `32`                      | 256-bit AES key provides 128-bit post-quantum security under Grover's algorithm.                                                                                                                   |
| `hkdf_info_strings.encryption` | `SecureMsg-v1-encryption` | Domain-separation label for HKDF when deriving the TOTP secret encryption key; prevents key reuse if additional derivation contexts are added later.                                               |

## messaging

| Key                  | Value   | Rationale                                                                                                     |
|----------------------|---------|---------------------------------------------------------------------------------------------------------------|
| `inbox_max_messages` | `50000` | Hard cap per recipient inbox; prevents a malicious sender from exhausting server storage.                     |
| `page_default`       | `50`    | Default page size for `GET /messages/`; limits response payload without requiring callers to specify a size.  |
| `page_max`           | `100`   | Maximum page size clients may request; prevents large single-request data dumps from slowing down the system. |

## auth

| Key                         | Value    | Rationale                                                                                                                                    |
|-----------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `access_token_ttl_seconds`  | `900`    | Short-lived access tokens limit the window of exposure if a token is stolen.                                                                 |
| `refresh_token_ttl_seconds` | `604800` | Medium-lived refresh tokens balance user convenience against refresh token compromise risk.                                                  |
| `preauth_token_ttl_seconds` | `60`     | Pre-auth token (issued after SRP, before TOTP) expires quickly to prevent an attacker using a captured pre-auth token to bypass SRP.         |
| `srp_session_ttl_seconds`   | `120`    | In-memory SRP session (between init and verify) expires after 2 minutes; limits the window for an attacker to complete a hijacked handshake. |
| `secret_token_bytes`        | `32`     | 256-bit entropy for SRP session IDs and JTIs provides 128-bit post-quantum security under Grover's algorithm.                                |
| `totp_window`               | `1`      | Allows ±1 time step (±30 s). RFC 6238 §5.2 recommends a window of at most 1 step to account for clock drift.                                 |
| `jwt_algorithm`             | `HS256`  | HMAC-SHA256; symmetric signing using `JWT_SECRET_KEY`;                                                                                       |

## server

| Key                       | Value                | Rationale                                                                                                                           |
|---------------------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| `db_pool_size`            | `10`                 | Baseline persistent connections kept open;                                                                                          |
| `db_max_overflow`         | `20`                 | Additional connections allowed above pool_size under load; total cap of 30 before requests queue.                                   |
| `time_for_enforced_http`  | `63072000`           | Long enough to cover typical browser cache lifetimes, short enough to recover from a misconfiguration without a multi-year lockout. |
| `block_framing`           | `DENY`               | `X-Frame-Options` value; prevents the app being embedded in any iframe, blocking clickjacking.                                      |
| `block_content_sniffing`  | `nosniff`            | `X-Content-Type-Options` value; stops browsers guessing MIME types, preventing content-sniffing attacks.                            |
| `allowed_content_sources` | `default-src 'none'` | `Content-Security-Policy` value; blocks all resource loading — appropriate for a pure API with no frontend.                         |
| `referrer_exposure`       | `no-referrer`        | `Referrer-Policy` value; suppresses the `Referer` header on outgoing requests, preventing URL leakage.                              |
