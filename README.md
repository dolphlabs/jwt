# jwt

Small, typed JWT support for slang backend services. The first release handles
JWS Compact tokens with HS256 and uses slang's existing `crypto`, `encoding`,
and `json` packages. Claims are your own JSON-compatible structs, so a service
keeps a single statically typed representation and does not allocate a dynamic
claims tree.

## Install after release

```text
pkg jwt git https://github.com/dolphlabs/jwt.git tag v0.1.0 dir src/jwt
```

After the repository is tagged `v0.1.0`, run `slangc get` and import `jwt`.
This package folder is not published or tagged yet, so the pin is a release
target rather than a resolvable dependency today.

## Use

```slang
import "jwt";

pub struct AccessClaims {
    sub: str,
    exp: int,
    nbf: opt[int],
    role: str,
}

let token = jwt.sign(claims, secret);
guard let compact = token else let e = err_of(token) { return err(e); }

let checked: result[AccessClaims, str] = jwt.verify(compact, secret);
guard let access = checked else { return err("unauthorized"); }
if !jwt.valid_at(access.exp, access.nbf, now_unix_seconds) {
    return err("unauthorized");
}
```

`secret` must be at least 32 random bytes. Do not use a human password as an
HS256 key. `sign` returns a fallible result for short keys and size limits;
`verify` rejects malformed tokens, non-canonical base64url, unsupported
algorithms and headers, invalid MACs, duplicate top-level claim names (including
escaped aliases), and claims that do not decode to the requested type. It checks
the top-level field count before typed decoding.

The default compact-token limit is 16 KiB and the default top-level claim limit
is 256 fields. `new_limits(token_bytes)` accepts 1 through 1,048,576 bytes and
keeps the 256-field default. `new_limits_with_fields(token_bytes, max_fields)`
sets both bounds, with 1 through 4,096 fields allowed. Pass the resulting
`Limits` to `sign_with_limits` / `verify_with_limits`. The MAC is checked before
the claims JSON is decoded.
Claims use the caller's typed structs directly; a plain value struct avoids a
dynamic JSON claims tree and does not require a GC-managed top-level object.
Verification builds a bounded temporary set of top-level names for duplicate
rejection, while claim values decode directly into the requested type. Strings,
lists, and maps inside claims still use their normal slang storage.

`verify` authenticates and decodes claims; it does not decide whether the
issuer, audience, subject, expiry, authorization, or replay policy is right for
your service. Check those after verification. `valid_at` checks required `exp`
and optional `nbf` NumericDate claims against caller-supplied Unix seconds.

## Scope

v1 deliberately supports only HS256 and one caller-selected key. It does not
fetch keys from `kid`, `jku`, or `x5u`, and does not implement RS256, ES256,
EdDSA, JWKS/OIDC, JWE, refresh, or revocation. Applications receiving tokens
from an external identity provider need that provider's public-key algorithm
and a trusted issuer-to-key configuration; this v1 package does not provide
that path.

See [JWT_PRD.md](JWT_PRD.md) for requirements, tests, and the security
boundary. The format follows [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html),
[RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), and
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), with the
algorithm-pinning guidance in [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).

## Measurements

`make bench` compares the package with a direct Go standard-library HS256
implementation using the same three-field claim and compact token. Both
implementations enforce the same protected-header checks, duplicate top-level
claim rejection, and 256-field limit, and produce identical token bytes. Each
binary warms verification, then signs and verifies 1,000 times per run; four
ABBA rounds collect 8,000 per-call samples for each operation. The run used one
CPU and a 2 GiB memory cap in the offline Linux container.

| Operation | slang p50 / p99 | Go p50 / p99 | Median batch throughput, slang / Go |
|---|---:|---:|---:|
| Sign | 3.909 / 27.794 µs | 1.886 / 11.131 µs | 192k / 395k ops/s |
| Verify | 8.302 / 66.698 µs | 9.054 / 66.622 µs | 91.3k / 72.2k ops/s |

These are single-process microbenchmark numbers, not API-server throughput.
Sign remains slower than Go; verification is in a similar range, with close p99
latency. Peak RSS in a process with 1,000 measured sign and verify samples
was 6,812 KiB for slang and 8,104 KiB for Go, including runtime startup and
benchmark sample storage.
