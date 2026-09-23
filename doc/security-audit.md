# Security audit and integration notes

Audit date: 2026-09-23. Baseline: `e4eb41658be8b1d4f46cb695837ebfe564cd2f25`.
Scope: all production code and tests in `lixenwraith/auth`, plus current auth
call sites in chess and planned use in vi-fighter/logwisp. This is a source audit
with regression, race, and bounded fuzz testing, not a formal protocol proof or
a production penetration test.

## Findings and corrections

| Area | Finding | Correction |
| --- | --- | --- |
| SCRAM replay | Verification cleared its atomic claim before deleting the handshake. A concurrent request could claim and successfully verify the same proof again. | Retain the claim through deletion; regression requires exactly one success under concurrent replay. |
| SCRAM client | Challenges did not need an active handshake or a nonce that extends the client's nonce. Restart retained old authentication material; final messages were reusable. | Explicit ordered states, nonce binding, one-use challenges/finals, terminal errors, and reset on restart. Recheck exported password length immediately before the KDF. |
| KDF downgrade | A hostile server could choose a tiny but valid KDF and collect a cheaply guessable client proof. | Clients default to a minimum of 64 MiB/3 iterations; an explicit local policy option supports trusted alternate profiles. |
| Resource exhaustion | Username/nonce/salt/proof inputs could allocate or retain unbounded data. Direct derivation and hash options could request unbounded Argon2 work; separate maxima allowed costly combinations. | Pre-decode byte limits, credential validation, common KDF limits at every entry point, and a combined memory×iterations ceiling. Retain the existing handshake-count cap and timeout. |
| Credential ownership | Server retained caller-owned credential pointers/slices without validation. Mutation could change challenges or keys, or race authentication. There was no account-removal API. | Validate and deep-copy credentials; add `Credential.Validate`, error-returning `AddCredential`, and `RemoveCredential`. Replacement/removal invalidates pending handshakes; successful final verification checks the active credential. |
| Account enumeration | Decoy salts changed on restart/replica boundaries. Last-added credential determined the unknown-user profile, allowing mixed profiles to disclose existence. | Add a constructor with a persistent shared decoy key; enforce one profile per server. Perform decoy HMAC work on known-user requests too. Document residual timing/application signals and load-before-serving requirements. |
| PHC migration | The common 32-byte digest branch admitted short salts that SCRAM import rejected. | Validate SCRAM salt length on both migration paths; reject the record consistently. Existing PHC verification remains available for legacy salts. |
| JWT policy | Signed tokens without a subject were accepted; future issued-at values were ignored. Unbounded token parsing and noncanonical signature encodings were accepted. | Require a nonempty subject and expiry; check issued-at; bound tokens; reject CR/LF, nonzero base64 pad bits, and unsupported critical headers. Keep algorithm pinning and configured issuer/audience checks. |
| Key/config ownership | HMAC secrets, RSA keys, and audience slices were borrowed. Invalid/weak RSA keys were not checked at construction. | Copy constructor inputs; validate RSA private material/public parameters and require at least 2048 bits. Accept PKCS#1 public PEM as well as PKIX. |
| Opaque tokens / HTTP | The allowlist could authenticate an explicitly stored empty token and its zero value panicked on insertion. Bearer parsing accepted embedded whitespace and required case-sensitive schemes. | Reject empty/oversized tokens, support the zero value, and enforce RFC 6750 Bearer syntax. Remove the unused password-header parser, its errors/tests/docs, and the generic scheme extractor. |

Canonical base64 checks also cover PHC records and imported SCRAM credentials.
Import accepts common JSON, YAML, and TOML numeric representations (`float64`,
`json.Number`, `int`, `int64`, unsigned integers) with exact range checks. Explicit
regressions reject NaN, infinities, fractions, negatives, and overflow. Transient
key buffers are cleared where practical; this is not a guarantee of memory erasure.

## Compatibility and rollout

Chess at `e3e465c9a2a81e4f5904a0e646c9812caa071c31` uses `HashPassword`,
`VerifyPassword`, `ValidatePHCHashFormat`, `GenerateHS256Token`, and
`ValidateHS256Token`. These signatures and JWT `extra` structure remain intact.
The one-off validator is a compatibility adapter to the common hardened parser;
it retains the existing five-minute leeway and lack of issuer/audience constraints.
Existing well-formed chess tokens remain valid. Its service tests and CLI package
were checked against this checkout using a temporary module replacement; no
changes to chess are included in this PR.

The inspected vi-fighter (`6fd727f848ac05ff6b76b85c8152aad995d9426e`) and logwisp
(`72c0a43c9f2ba017bf2fd62319077b3655ee4514`) revisions do not yet import auth.
Their future deployment integration is outside this package PR.

SCRAM message JSON fields and the valid transcript encoding stay unchanged.
`NewScramClient` accepts optional local minimum-cost policy options; ordinary
two-argument calls retain their syntax, with stronger default challenge policy.
`AddCredential` now returns an error; callers should check it. Calls used as
statements still compile, but interfaces requiring the old no-result signature
must be updated (none occur in the inspected consumers). Intentionally rejected
inputs include malformed identities/nonces, mixed SCRAM profiles, noncanonical
base64, oversized tokens, and KDF parameters above the new budget. Short-salt PHC
records must be re-enrolled before SCRAM migration. A server's profile remains
fixed after removing its last credential to keep decoy responses stable.

## Integration boundaries

- **Transport:** this Argon2/JSON protocol is not standard SASL SCRAM-SHA-256 and
  has no channel binding. Authenticated TLS/WSS and connection-bound exchange
  handling belong to the caller. Always verify the server final before trusting
  the login result or a token delivered with it.
- **Registration/storage:** generate salts with `NewCredential`; protect both
  credential keys and the shared decoy secret. Do not retain the old PHC salted
  password after migration unless a separate authentication path requires it.
- **Denial of service:** enforce request/frame limits before JSON decoding,
  deadlines, rate limits, and a RAM-appropriate cap on simultaneous KDF calls.
  Package ceilings are per operation. Credential count and opaque-token count
  are application-controlled and are not capped by the package.
- **Authorization/revocation:** scope JWT issuer/audience to the receiving
  service. HS256 verifiers can issue tokens; use RS256 when services should only
  verify. Check session state when logout/rotation needs immediate revocation.
  Removing a SCRAM credential cannot retract sessions already issued by the app.
- **Privacy:** map authentication failures to suitable public responses; avoid
  logging passwords, proofs, keys, or bearer tokens. The decoy mechanism reduces
  enumeration signals but does not promise constant-time network behavior.

## Performance

`NewCredential` performs one Argon2 derivation; provisioning through
`HashPassword` followed by `MigrateFromPHC` performs two. Existing PHC migration
continues to reuse its verification KDF for the normal 32-byte digest.

JWT managers now construct their immutable parser once, and the legacy HS256
helper shares a parser. No password-strength defaults were reduced. RSA key
validation/copying occurs at construction. The server's proof path performs
bounded hash/HMAC operations, with no Argon2 work.

On Go 1.27.1/linux-amd64, three local benchmark samples measured direct
provisioning at 6.61–7.54 ms and ~8.39 MB allocated, versus 13.10–13.72 ms and
~16.79 MB for hash-then-migrate (8 MiB/1-iteration **test** profile). JWT
sign-plus-verify allocations dropped from 88 to 85 per operation (~5133 to
4973 bytes); median time was 14.67 µs before and 13.73 µs after. These short local
samples are indicative, not a production capacity claim.

## Validation

Local validation on Go 1.27.1/linux-amd64 passed `go vet ./...` and
`go test -race -count=1 -coverprofile=... ./...`, with **98.1% statement coverage**.
All seven fuzz targets passed 10-second, two-worker campaigns (over 1.8 million
executions combined); the client target was rerun after adding minimum-cost
policy. These are smoke campaigns, not exhaustive fuzzing. Chess's service tests
and CLI compilation also passed after the dependency update.

`govulncheck v1.8.0` reported zero vulnerabilities in reachable calls or imported
packages. Its only remaining module-level advisory is **GO-2026-5932** for
`golang.org/x/crypto/openpgp`, which this package does not import and which has no
fixed release. The scan used Go 1.27.1; consumers must also keep their Go runtime
patched.

The test suite includes concurrent replay, registration/removal, credential ownership,
protocol sequencing, resource ceilings, canonical encoding, RSA validation,
JWT trust scopes, and the compiled end-to-end example. Seven fuzz targets cover
PHC parsing/verification, credential import, JWT verification, Bearer parsing,
and both SCRAM peer inputs. CI runs vet, race tests, and bounded fuzz smoke tests.

Dependencies were updated to `golang.org/x/crypto v0.57.0` and its
`golang.org/x/sys v0.48.0` requirement without raising Go 1.26. The Argon2 source
is unchanged from v0.54.0. The update includes fixes for SSH advisories
GO-2026-6303, GO-2026-6354, and GO-2026-6355 in unused sibling packages.

## Primary references

- [RFC 5802, SCRAM exchange and security considerations](https://www.rfc-editor.org/rfc/rfc5802.html)
- [RFC 9106, Argon2 inputs and recommended parameters](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 8725, JWT best current practices](https://www.rfc-editor.org/rfc/rfc8725.html)
- [RFC 6750, Bearer token syntax and transport](https://www.rfc-editor.org/rfc/rfc6750.html)
- [Go vulnerability database](https://vuln.go.dev/)
