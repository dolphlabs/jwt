# jwt

Small, typed JWT support for slang backend services: JWS Compact tokens with
HS256/384/512, RS256, PS256, ES256 and EdDSA, keys bound to one algorithm,
JWK and JWKS, a caching JWKS client, and OpenID Connect ID-token
verification, over slang's `crypto`, `encoding`, `json` and `httpc` packages. Claims are your own JSON-compatible structs, so a service
keeps a single statically typed representation and does not allocate a dynamic
claims tree.

## Install

v0.2.0 requires a slang built with the `crypto` additions (dolphlabs/slang
PR "feat(crypto): add AEAD, Ed25519, ECDSA P-256, RSA signing, SHA-512,
HKDF", the release after 0.2.5). v0.1.0 (HS256 only) works with slang 0.2.2
or later. In your project's `slang.project`:

```text
pkg jwt git https://github.com/dolphlabs/jwt.git tag v0.2.0 dir src/jwt
```

Then run `slangc get` and `import "jwt";`.

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

## Keys bound to an algorithm

`sign`/`verify` above are HS256 with a raw secret. For anything else, make a
`Key`, which carries its algorithm, and use `sign_with` and `verify_with`:

```slang
let signing = jwt.ec_private_key(scalar, "2026-11");          // ES256
let token = jwt.sign_with(claims, signing ?? fallback);       // {"alg":"ES256","kid":"2026-11",...}

let keys = jwt.parse_jwks(jwks_json);                         // result[[Key], str]
let checked: result[AccessClaims, str] = jwt.verify_with(token, keys ?? []);
```

| Algorithm | Private key | Public key |
|---|---|---|
| HS256, HS384, HS512 | `hmac_key(alg, secret, kid)` (secret at least 32/48/64 bytes) | the same key |
| RS256, PS256 | `rsa_private_key(alg, pem, kid)` | `rsa_public_key(alg, n, e, kid)` |
| ES256 | `ec_private_key(scalar32, kid)` | `ec_public_key(x32, y32, kid)` |
| EdDSA (Ed25519) | `ed25519_private_key(seed32, kid)` | `ed25519_public_key(pub32, kid)` |

`public_of(key)` gives the publishable half, and `jwk_of(key)` gives its public
JWK text for your own JWKS endpoint. `key_from_jwk(text)` and
`parse_jwks(text)` read published keys (RSA, EC P-256, OKP Ed25519). A JWK
without `alg` gets the one its type implies (RSA is RS256). Encryption keys
and unsupported curves in a set are skipped, and private (`d`) or secret
(`k`) members are refused.

**Verification never lets the token choose the primitive.** The header's
`alg` must be the algorithm of a key you passed, and its `kid`, when present,
must be that key's. So an HS256 token "signed" with an RSA public key as the
HMAC secret, the classic key-confusion attack, finds no HS256 key and fails.
With no `kid`, each key of the header's algorithm is tried (at most 8). A
duplicate or `null` `kid`, like `crit` and `b64`, is rejected, and `jku`,
`x5u` and `jwk` headers are never used to find a key. The signature is
checked before the claims are decoded. Verification fails with
`jwt.ERR_UNKNOWN_KID` when the token names a kid none of the keys has.

## JWKS client

```slang
let issuer_keys = jwt.new_jwks("https://www.googleapis.com/oauth2/v3/certs");
// share one Jwks between every task
let r: result[Claims, str] = jwt.verify_jwks(token, issuer_keys ?? fallback, deadline);
```

A `Jwks` fetches the set over HTTPS (https only) and keeps it for an hour, or
less if the response's `Cache-Control: max-age` says so. A token with an
unknown `kid` triggers one refetch and one retry, which is how a key rotation
at the issuer is picked up. Fetches are rate-limited to one per 30 seconds,
whatever triggers them, so a flood of tokens with made-up kids cannot make
it hammer the issuer. Concurrent misses wait for one fetch rather than each
starting their own. A failed refresh keeps the old keys, so a brief outage at
the issuer does not log everyone out. `new_jwks_with(url, max_age_seconds,
min_interval_seconds)` sets both bounds, and `jwks_set_keys` loads a set that
arrived some other way.

## OpenID Connect ID tokens

```slang
let rules = jwt.id_token_rules("https://accounts.google.com", client_id);
rules.nonce = some(nonce_sent_with_the_login);
let id: result[GoogleClaims, str] =
    jwt.verify_id_token_jwks(token, google_keys, rules, now_unix_seconds, deadline);
```

`verify_id_token` (with keys) and `verify_id_token_jwks` (with a client)
check the signature, then the rules of OpenID Connect Core 3.1.3.7 before
decoding into your type:
- `iss` equals the issuer exactly;
- `aud` (a string or a list) contains your client id;
- with several audiences, `azp` is present and equals it;
- `exp` and `nbf` hold, within `leeway_seconds` (60 by default);
- `iat` is not in the future;
- the `nonce` matches when you set one.

Each failure has its own error.

## Scope

Not implemented: JWE, JWS JSON serialization, OIDC discovery (configure the
issuer and JWKS URL yourself), ES384/ES512/RS384/RS512, refresh tokens and
revocation. `verify` and `verify_with` prove integrity and the claims' type;
issuer, audience, expiry and authorization policy stay with you, or use
`verify_id_token` for ID tokens.

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
