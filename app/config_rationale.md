# Security Configuration Rationale

Explains the reasoning behind every security-relevant value in `config.json`.
Non-security values (e.g. HKDF info strings) are omitted.

---

## crypto

**nonce_length_bytes: 12**
Other lengths are hashed internally by GCM, wasting entropy and creating
birthday-paradox collision risk in the authentication tag.
NIST SP 800-38D §8.2 specifies 96-bit as the only size that avoids this.

**nonce_strategy: counter**
Random nonces collide after ~2^48 messages under the same key (birthday paradox),
breaking GCM's integrity guarantees. A counter guarantees uniqueness with no
probability involved. NIST SP 800-38D §8.2.1 recommends deterministic construction.

**max_message_bytes: 10485760**
The AES-256-GCM block limit (~64 GiB, NIST SP 800-38D §B.2) is not a practical
constraint for messages. 10 MiB is a DoS protection limit — an uncapped upload
would allow an attacker to exhaust server memory with a single request.

**sender_key_rotation: on_membership_change**
Matches the Signal Sender Key protocol exactly. The chain key ratchets forward
per message — each message gets a unique derived key, so per-key invocation
limits (NIST SP 800-38D §B.2) are never approached. Redistribution only on
membership change is sufficient because per-message forward secrecy is already
guaranteed by the ratchet, not by periodic rotation.

**ml_kem_variant: ML-KEM-1024**
ML-KEM-1024 is NIST security level 5 (~AES-256 equivalent), matching our AES-256-GCM
session cipher exactly — no mismatched security levels in the stack. ML-KEM-768
(level 3, ~AES-192) would be the weakest link against a quantum attacker.
Signal's PQXDH specification uses ML-KEM-1024 for this same reason (NIST FIPS 203).

**signature_algorithm: Ed25519**
Ed25519 only — no post-quantum signature scheme, following Signal's PQXDH decision.
The quantum threat to signatures is not retroactive: forging a signature requires a
quantum computer at the moment of attack, unlike KEMs where ciphertext can be harvested
now and decrypted later. Post-quantum signatures (e.g. ML-DSA-65) are ~3,293 bytes vs
64 bytes for Ed25519, significantly bloating key bundles. Known limitation: upgrade
required if capable quantum computers emerge (RFC 8032).

**classical_kem: X25519**
If ML-KEM has an undiscovered flaw, X25519 still protects the session — both
must be broken simultaneously for the handshake to be compromised.
IETF RFC 9180 §9.7 recommends hybrid combinations during the PQ transition period.

**argon2_variant: argon2id**
Pure Argon2i is vulnerable to GPU parallelism attacks; pure Argon2d leaks
secrets via cache side-channels. argon2id combines both defences.
RFC 9106 §4 and OWASP recommend argon2id as the default variant.

**argon2_memory_cost_kb: 65536**
Below 64 MiB a GPU can run thousands of parallel guesses simultaneously,
making offline dictionary attacks cheap.
OWASP Password Storage Cheat Sheet specifies 64 MiB as the minimum for argon2id.

**argon2_time_cost: 3**
Fewer iterations reduce the work an attacker must do per password guess
proportionally, weakening resistance to offline attacks.
RFC 9106 §4 specifies t=3 as the minimum recommended iteration count.

**argon2_hash_len: 32**
A shorter output becomes the bottleneck — an attacker only needs to find a
collision in the hash output rather than crack the full password space.
32 bytes matches the AES-256 key size, keeping security levels consistent.

**symmetric_key_length_bytes: 32**
AES-256 key size used for Double Ratchet chain keys and message keys.
32 bytes = 256 bits; matches the AEAD algorithm choice (AES-256-GCM).

**totp_key_length_bytes: 32**
AES-256 key size for encrypting TOTP secrets at rest. Kept separate from
symmetric_key_length_bytes so the two can diverge independently if needed.

**hkdf_info_strings**
Without domain separation, a key derived for message encryption could be
submitted as an auth token — cross-purpose key misuse attacks become possible.
RFC 5869 §3.2 requires distinct info strings per use case to prevent this.

---

## auth

**access_token_ttl_seconds: 900**
A stolen bearer token is valid until expiry; short TTL caps the attacker's window.
Device-Bound Session Credentials (DBSC) would be a stronger solution — binding
tokens to hardware keys makes theft useless — but DBSC requires browser or TPM
support unavailable in the C++ desktop client.
OWASP recommends a maximum of 15 minutes (900 seconds) for unbound bearer tokens.

**refresh_token_ttl_seconds: 604800**
7 days (604800 seconds). Refresh tokens are long-lived by design — they exist so
users are not forced to re-authenticate frequently. They are single-use (rotated
on each refresh) and blocklisted on logout to limit the window if stolen.

**secret_token_bytes: 32**
256 bits of entropy used for all server-generated secret tokens: SRP session IDs,
JWT IDs (jti), and message revocation tokens. 256 bits makes brute-force infeasible
regardless of the token's lifetime.

**srp_session_ttl_seconds: 120**
The server holds ephemeral SRP state between /srp-init and /srp-verify.
If the client abandons the handshake, this state must expire to prevent
unbounded memory growth. 120 seconds is generous for any legitimate client
latency while keeping the attack surface for session fixation narrow.

The `session_id` returned by /srp-init is the lookup key for this state.
It is not cryptographically secret — it does not protect the password —
but it must be unguessable (32 random bytes / 64 hex chars from a CSPRNG)
to prevent a third party from racing in a forged client proof against
another user's in-flight SRP session.

**preauth_token_ttl_seconds: 60**
Without a short TTL, an attacker who steals a password has unlimited time to
brute-force the 6-digit TOTP code (only 10^6 possibilities).
TOTP codes rotate every 30 seconds; 60 seconds allows one rotation window only.

**totp_window: 1**
A wider window allows more valid codes simultaneously, giving an attacker more
valid guesses before the code rotates.
RFC 6238 §5.2 recommends a window of at most 1 step to account for clock drift.

**jwt_algorithm: HS256**
HS256 (HMAC-SHA256) is used for JWT signing over TLS. RS256/ES256 are needed
only when third parties verify tokens — unnecessary here since the server both
issues and verifies. The signing secret is generated fresh per deployment from a CSPRNG.

---

## rate_limits

**auth: "10/minute"**
Limits credential stuffing and TOTP brute-force. 10/min allows legitimate users
while making automated attacks impractical.
OWASP Authentication Cheat Sheet recommends strict rate limiting on all auth endpoints.

**refresh: "20/minute"**
Refresh tokens are rotated on every use — an attacker hammering /refresh to enumerate
valid tokens would exhaust their window quickly. 20/min is generous for legitimate
clients (background token refresh) while making token enumeration impractical.

**logout: "20/minute"**
Logout hits the token blocklist on every call. 20/min matches the refresh limit
and prevents blocklist-flooding DoS from an authenticated attacker.

**messages: "60/minute"**
Prevents message flooding DoS. 60/min is generous for human use while blocking
scripted spam.

**keys: "30/minute"**
Key bundle fetches happen at session setup, not in a tight loop. 30/min is
sufficient for any realistic client while preventing bulk key harvesting.

**groups: "30/minute"**
Group management operations (create, get info, add/remove members). 30/min covers
normal use; tighter than messages because these operations mutate group membership.


---

## validation

**username_min_length: 3**
Usernames shorter than 3 characters are impractical and increase the risk of
accidental collision with reserved names or single-character identifiers.

**username_max_length: 32**
Caps storage and display width. 32 characters covers all realistic usernames
while preventing oversized strings being stored in the database.

**alnum_re: "^[a-zA-Z0-9]+$"**
Restricts usernames to letters and digits only, excluding characters with special
meaning in URLs, HTML, or SQL.

**hex_re: "^[0-9a-fA-F]+$"**
Validates that SRP salt, verifier, and proof fields are valid hex strings before
any `bytes.fromhex()` call, rejecting malformed input at the schema layer.

---

## server

**app_name: "SecureMsg"**
Used as the TOTP issuer name in provisioning URIs shown to users in their
authenticator app. Must match the name users expect to see.

**max_upload_bytes: 10485760**
Hard limit at the HTTP layer (before parsing) matching max_message_bytes.
Prevents memory exhaustion from oversized request bodies regardless of endpoint.

**tls_min_version: TLSv1.3**
TLS 1.2 permits cipher suites without forward secrecy — one stolen server key
decrypts all past recorded sessions. TLS 1.3 mandates ephemeral key exchange
on every handshake. RFC 8446 deprecates all TLS versions below 1.3.

**cors_origins: []**
A wildcard CORS policy lets any malicious website make authenticated API
requests using the victim's session credentials, enabling CSRF-style attacks.
Must be set explicitly per deployment.
OWASP CORS Security Cheat Sheet requires explicit origin allowlists.

**db_url: "sqlite://"**
SQLAlchemy connection URL passed to `create_engine`. The empty path (`sqlite://`
with no file component) is intentional: the actual database path is supplied via
the `creator` callable, which opens a SQLCipher connection directly. Using a
plain `sqlite:///path` URL would bypass SQLCipher and open an unencrypted file.
