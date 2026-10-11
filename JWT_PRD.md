# JWT package PRD

## Goal

Provide a small, standalone, installable JWT package for slang backend services. The first consumer is zokor middleware, where applications need to issue and verify bearer tokens into their own typed claim structs. Prefer a small pure-slang package over compiler or runtime changes, and keep per-request allocations proportional to the bounded token size.

## v1 scope

- JWS Compact Serialization with HS256 only.
- Generic typed claims: `sign[T](claims, key)` serializes a slang JSON-compatible object; `verify[T](token, key)` authenticates first, then decodes the payload into the caller's type.
- A default bounded token size plus an explicit limits API for applications with larger claims.
- An explicit time helper for `exp` and `nbf`; time is supplied by the caller so the package has no hidden clock or environment access.
- Source-only package under `src/jwt/`, with a pinned consumer compile test and unit tests for valid and hostile inputs.

## Security and parsing requirements

- Always generate and verify `alg: HS256`; reject `none`, every other algorithm, and malformed or unsupported protected-header features. Never select a crypto primitive from an untrusted header.
- Reject `crit` and `b64` protected parameters, including explicit `null` and escaped member-name spellings; reject duplicate `alg`/`typ` members and `typ: null`.
- Reject duplicate top-level claim names, including equivalent escaped spellings, before typed claim decoding. Cap the number of top-level claim fields at 256 by default and 4,096 maximum; allow callers to choose a lower or higher bounded value. Verification may keep a bounded temporary set of field names, but must decode claim values directly into the requested type.
- Require an HS256 key of at least 32 bytes, matching RFC 7518. Treat the key as random secret bytes, not a human password.
- Require exactly three compact segments, no whitespace or padding, canonical base64url encodings, bounded input, a valid JSON object header, and a JSON object claims payload.
- Verify the MAC over the original encoded `header.payload` bytes before decoding the claims payload. Compare the fixed-length MAC without content-dependent early exit.
- Never use received `kid`, `jku`, or `x5u` values to load a key or make network requests. v1 uses exactly the caller-supplied shared key.
- `verify` proves integrity and typed decoding only. The application must still enforce issuer, audience, expiration, subject, authorization, and replay policy. `valid_at` covers only the supplied `exp` and optional `nbf` values.
- Error values are stable, concise, and contain no token or key material.

## API direction

```slang
let token = jwt.sign(claims, secret);
let checked: result[AccessClaims, str] = jwt.verify(token, secret);
if let access = checked {
    if !jwt.valid_at(access.exp, access.nbf, now) { /* reject */ }
}
```

The default API should be the short path. `Limits` and explicit `_with_limits` functions allow larger application-selected token and top-level claim-field bounds without removing the hard maxima. `new_limits` changes only the token-size bound; `new_limits_with_fields` configures both. Claim codecs reuse slang's existing generic `json.encode` and `json.decode`; do not introduce an untyped claim tree.

## Deliberate non-goals for v1

RS256/ES256/EdDSA and public-key parsing; JWKS and OIDC discovery; JWE; JWS JSON serialization; token refresh, storage, revocation, or replay databases; HTTP middleware. Public-key/OIDC support can be added later as an independent algorithm family with keys bound to that one algorithm.

## Validation and performance

- Verify the RFC 7515 HS256 vector and a fixed RFC-derived signing vector; compare the complete emitted token with a Go standard-library implementation.
- Cover changed header, payload and MAC; `none` and unknown algorithms; weak keys; malformed segment counts; padded and noncanonical base64url; unsupported critical or unencoded-payload headers; malformed/non-object JSON; invalid typed claims; duplicate standard and custom claims, escaped duplicate aliases, claim-field boundaries, and token-size boundaries.
- Baseline evidence: the existing compiler cannot resolve the new `jwt` import before this package is present. The package consumer passes normally and with `SLANG_GC_VERIFY_MINOR=1 SLANG_GC_NURSERY_KB=16` (`missed=0`). The full slang compiler suite was attempted but did not complete in the offline container: Git is absent for local package fixtures and the run hit its 600-second cap during stress tests. An independent generated-C sweep compiled 184 sources with zero warnings; three Git-dependent package fixtures could not be compiled.
- The isolated same-host benchmark used equivalent protected-header and duplicate-claim checks. It measured 3.909/27.794 µs p50/p99 for slang sign and 8.302/66.698 µs for verify, versus 1.886/11.131 µs and 9.054/66.622 µs for Go. Median batch throughput was 192k/91.3k ops/s for slang and 395k/72.2k for Go; peak RSS was 6,812 KiB vs 8,104 KiB for a process with 1,000 measured sign and verify samples. These are container microbenchmarks, not server claims.
- Removing one dot-count scan was tested with randomized ABBA ordering and made no measurable latency improvement; retain the early malformed-token rejection. A four-round ABBA comparison of the separate count-only signing scan showed no consistent latency change, while `SLANG_GC_NURSERY_KB=16` allocation stats for a process with 1,000 measured sign and verify iterations plus setup/warmup fell from 70,090 allocations / 5,374,956 bytes to 69,089 / 5,294,040. This removes one temporary list allocation per signature. A strict native base64url decoder is a possible future compiler/runtime optimization because canonical re-encoding currently costs an extra pass and allocation.

## Standards

- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515.html)
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html)
- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519.html)
- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html)
