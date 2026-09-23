# auth

Small, independent authentication components for Go 1.26+: Argon2id password
hashing, Argon2-SCRAM, HS256/RS256 JWTs, and opaque token validation.

## Argon2-SCRAM

This is a **package-specific JSON challenge/response protocol using Argon2id and
HMAC-SHA256**, not standard SASL SCRAM-SHA-256. Both peers must implement this
protocol. It does not implement SASLprep or TLS channel binding. Use authenticated
TLS (HTTPS/WSS for HTTP/WebSocket transports), including server certificate and
hostname verification. SCRAM does not encrypt subsequent application traffic.

Provision directly; do not create a PHC hash just to convert it:

```go
cred, err := auth.NewCredential(username, password)
if err != nil {
    return err
}
// Persist cred.Export() in protected storage, then load with ImportCredential.
if err := server.AddCredential(cred); err != nil {
    return err
}
```

For a service, construct `server` using
`NewScramServerWithDecoyKey(decoyKey)` and handle its error. Provision and persist
at least 32 random bytes for this key, separately from credentials. Reuse it across
restarts and all replicas sharing the credential database. `NewScramServer()`
remains available for single-instance use, but its random key changes unknown-user
salts on every restart, which can reveal account existence to repeated probes.
Always call `server.Stop()` at shutdown.

The exchange is:

1. Client: `NewScramClient(username, password)` then `StartAuthentication()`.
2. Server: `ProcessClientFirstMessage(first.Username, first.ClientNonce)`.
3. Client: `ProcessServerFirstMessage(challenge)`.
4. Server: `ProcessClientFinalMessage(proof.FullNonce, proof.ClientProof)`.
5. Client: `VerifyServerFinalMessage(final)` before accepting login or any token
   delivered with it.

Clients reject costs below 64 MiB and 3 iterations by default, preventing a
hostile server from requesting a cheaply guessable password proof. For a trusted
deployment with a different profile, pass `WithMinArgonCost(iterations, memoryKiB)`
to `NewScramClient`. Choose this policy locally; never copy it from a challenge.
Invalid minimum configuration is rejected by `StartAuthentication`.

Check every error and abort the exchange on failure. Only a successful **server
final** authenticates a user; use its `Username`, never a separate identity from
an untrusted request. Bind the exchange to its connection/request context in the
application. See [example_test.go](example_test.go) for a complete exchange.

`ScramServer` is safe for concurrent use. Each `ScramClient` belongs to one
exchange and must not be shared concurrently. Starting again discards previous
state. Challenges and final messages are single-use; errors consume client state.
`Reset` clears transient keys while retaining the public username/password fields
for retry. Secret clearing is best effort; Go strings and runtime copies cannot
be reliably erased.

All credentials in a server must share Argon2 parameters and salt length;
`AddCredential` returns `ErrSCRAMCredentialProfile` otherwise. Load the full
credential set before accepting traffic and use identical profiles on replicas.
Unknown users receive stable decoy challenges and fail at the proof step with
`ErrInvalidCredentials`, as wrong passwords do. This reduces enumeration signals;
it is not a guarantee against statistical timing analysis. Application responses,
registration, logging, and rate limits must not disclose account existence.

`AddCredential` validates and copies its input; check the returned error.
Replacement and `RemoveCredential(username)` invalidate pending handshakes for
that user. They do not revoke already issued JWTs or application sessions.
`Stop` discards pending handshakes and rejects further authentication.

## Password hashing and migration

`HashPassword(password, opts...)` returns an Argon2id PHC record.
`VerifyPassword(password, phc)` verifies it. New passwords must contain 8–1024
**bytes**; applications should apply their own password policy. Verification and
explicit `DeriveCredential` allow older shorter passwords. Defaults are 64 MiB,
3 iterations, 4 lanes, a random 16-byte salt, and a 32-byte digest. Do not use the
low-cost test parameters in production.

`WithTime`, `WithMemory` (KiB), and `WithThreads` configure hashing or
`NewCredential`; zero options retain defaults. All KDF entry points reject
invalid or excessive parameters before allocation. Existing short PHC salts of
8–15 bytes remain verifiable but cannot be migrated to SCRAM; reset/re-enroll
those credentials with fresh salts.

`MigrateFromPHC(username, password, phc)` verifies the password and derives a
SCRAM credential, normally reusing the single KDF result. A non-32-byte PHC
digest requires a second derivation. After migration, remove the old PHC record
unless it is still needed by a separate authentication path: its digest is the
salted password from which both SCRAM keys can be derived.

`ValidatePHCHashFormat` checks syntax, encoding, and structural parameter limits
without running the KDF. A syntactically valid record may still exceed execution
limits. PHC and SCRAM base64 fields must be canonical, with no CR/LF.

## JWTs

Create one manager per key and service policy, then reuse it concurrently:

```go
manager, err := auth.NewJWT(secret, // at least 32 cryptographically random bytes
    auth.WithIssuer("lixen-auth"),
    auth.WithAudience([]string{"vi-fighter"}),
    auth.WithTokenLifetime(15*time.Minute),
    auth.WithLeeway(0))
if err != nil {
    return err
}
token, err := manager.GenerateToken(userID, map[string]any{"session_id": sessionID})
if err != nil {
    return err
}
subject, claims, err := manager.ValidateToken(token)
// Check err, then authorize subject and the application claims for this action.
```

Generation uses `sub`, `exp`, `iat`, `nbf`, and configured `iss`/`aud`. Application
claims remain nested under `extra` and cannot overwrite registered claims.
Validation requires expiration and a nonempty subject, validates `nbf` and `iat`
when present, pins the signing algorithm, and enforces configured issuer and
**any matching audience**. No identity/claims are returned on failure.
Use `errors.Is` with package errors. `ErrTokenMissingClaim` covers missing or
mismatched issuer/audience; `ErrTokenNotYetValid` also covers future `iat`.

For logwisp and vi-fighter, use distinct audiences and verify them at each
service; use separate keys where trust differs. With HS256, every verifier can
mint tokens. For separate signing and verification trust, use
`NewJWTRSA(privateKey)` and `NewJWTVerifier(publicKey)` with the same claim policy.
RSA keys must be valid and at least 2048 bits. PEM constructors accept PKCS#1 or
PKCS#8 private keys and PKCS#1 or PKIX public keys. Constructors copy keys and
audiences; create a new manager for rotation and synchronize its replacement in
the application. Options are for construction only.

The default lifetime is 24 hours and the existing clock leeway is **5 minutes**,
including after expiration. Explicitly set `WithLeeway(0)` or a small justified
skew for new services. Expiry does not revoke an otherwise valid JWT on logout:
check a persisted session or a revocation policy when immediate revocation is
required. Do not place passwords, credential keys, or secrets in JWT claims;
JWT payloads are readable by the holder.

`GenerateHS256Token` and `ValidateHS256Token` retain chess's API and `extra` JSON
shape. The validator shares the hardened validation path, but intentionally
retains the legacy five-minute leeway and no issuer/audience constraint. Prefer
a configured manager for new integrations. Existing chess hashing and CLI PHC
validation functions also retain their signatures.

## Opaque tokens and HTTP

`ParseBearerToken(header)` parses the case-insensitive Bearer scheme and RFC
6750 token alphabet. It rejects whitespace inside tokens, misplaced padding,
and oversized input. It only extracts a token; always validate it afterward.

`SimpleTokenValidator` is a concurrent, in-memory allowlist keyed by SHA256(token).
Its zero value works. Generate high-entropy opaque tokens with `crypto/rand.Text`,
then use `AddToken`, `ValidateToken`, and `RemoveToken`. Empty and oversized tokens
are never accepted. There is no TTL or persistence; use JWTs or application
session storage when needed. `AddToken` ignores invalid lengths for API stability.

## Resource limits

| Input/resource | Limit |
| --- | --- |
| Password | 1024 bytes at every KDF entry |
| SCRAM username | 1–256 UTF-8 bytes; no control characters, comma, or equals |
| Client nonce / combined nonce | 256 / 512 printable ASCII bytes; no comma |
| SCRAM salt / key / proof | 16–64 / 32 / 32 decoded bytes |
| PHC record / salt / digest | 256 encoded / 8–64 / 16–64 decoded bytes |
| Argon2 execution | memory ≤256 MiB, iterations ≤16, lanes ≤16, memory ≥8×lanes KiB |
| SCRAM client minimum | 64 MiB and 3 iterations by default; trusted local policy can override |
| Argon2 combined work | memory×iterations ≤786432 KiB-passes (4×default) |
| Pending server handshakes | 4096, with a 30-second timeout |
| JWT / opaque token | 16 KiB |

These are per-operation ceilings, not aggregate memory/CPU quotas. Set transport
body/frame limits **before decoding**, use connection/request deadlines, rate
limit by peer/account, and bound concurrent KDF calls for your available RAM.
The server proof path only hashes/HMACs; registration, migration, password checks,
and SCRAM clients run Argon2. Apply limits to all of those routes. Username and
password normalization is application policy and must be identical at both ends.

## Verification

```sh
go vet ./...
go test -race -count=1 ./...
go test -run '^$' -bench . -benchmem

# Run each target separately; keep worker count bounded for KDF fuzzing.
for target in FuzzParsePHC FuzzVerifyPassword FuzzImportCredential FuzzValidateHS256Token FuzzParseBearerToken FuzzScramServerMessages FuzzScramClientMessages; do
    GOMAXPROCS=2 go test -run '^$' -fuzz "^${target}$" -fuzztime=60s -parallel=2
done
```

CI runs race tests, vet, and short fuzz campaigns. Fuzz KDF paths use bounded test
costs; deterministic tests cover production limits without allocating at those
limits. See [the audit report](doc/security-audit.md) for findings and scope.
