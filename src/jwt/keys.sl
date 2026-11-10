// Keys bound to one algorithm, and JWS signing and verification with them.
//
// A Key carries its algorithm. Verification accepts a token only when its
// header names the algorithm of a key it was given (and that key's kid,
// when the header has one), so a header can never steer verification to
// another primitive: an HS256 token "signed" with an RSA public key as the
// HMAC secret -- the classic key-confusion attack -- finds no HS256 key and
// fails (RFC 8725 3.1, 3.2). Received jku, x5u and jwk headers are never
// used to find a key.

import "crypto";
import "encoding";
import "json";
import "strings";

// The JWS algorithms supported (RFC 7518, RFC 8037).
pub enum Alg {
    HS256,
    HS384,
    HS512,
    RS256,
    PS256,
    ES256,
    EdDSA,
}

// A signing or verification key, bound to one algorithm. Build one with
// the constructors below or key_from_jwk; the fields are the
// representation. kid is "" when the key has none.
pub struct Key {
    alg: Alg,
    kid: str,
    secret: bytes,
    private: bytes,
    public: bytes,
    pem: str,
    n: bytes,
    e: bytes,
    can_sign: bool,
}

// The error verification returns when the token names a kid none of the
// keys has: a JWKS cache refreshes on it (see verify_jwks).
pub let ERR_UNKNOWN_KID = "jwt key id is not known";

// The algorithm's name in a JWS header.
pub fn alg_name(a: Alg) -> str {
    return switch a {
        case Alg.HS256 { "HS256" }
        case Alg.HS384 { "HS384" }
        case Alg.HS512 { "HS512" }
        case Alg.RS256 { "RS256" }
        case Alg.PS256 { "PS256" }
        case Alg.ES256 { "ES256" }
        case Alg.EdDSA { "EdDSA" }
    };
}

fn blank_key(a: Alg, kid: str) -> Key {
    return Key { alg: a, kid: kid, secret: b"", private: b"", public: b"",
                 pem: "", n: b"", e: b"", can_sign: false };
}

// ---- constructors -------------------------------------------------------------

// An HMAC key: HS256, HS384 or HS512 with a secret of at least the hash
// length (32, 48, 64 bytes; RFC 7518 3.2). Random bytes, not a password.
pub fn hmac_key(a: Alg, secret: bytes, kid: str) -> result[Key, str] {
    let need = 0;
    if a == Alg.HS256 {
        need = 32;
    } else if a == Alg.HS384 {
        need = 48;
    } else if a == Alg.HS512 {
        need = 64;
    } else {
        return err("hmac_key takes HS256, HS384 or HS512");
    }
    if len(secret) < need {
        return err(alg_name(a) + " key must contain at least " + to_str(need) + " random bytes");
    }
    let k = blank_key(a, kid);
    k.secret = secret;
    k.can_sign = true;
    return ok(k);
}

// An RSA private key (PEM) for RS256 or PS256. Its public half comes with
// it, so the same Key verifies.
pub fn rsa_private_key(a: Alg, pem: str, kid: str) -> result[Key, str] {
    if a != Alg.RS256 && a != Alg.PS256 {
        return err("rsa_private_key takes RS256 or PS256");
    }
    let rn = crypto.rsa_public_n(pem);
    guard let n = rn else let e = err_of(rn) { return err(e); }
    let re = crypto.rsa_public_e(pem);
    guard let ex = re else let e = err_of(re) { return err(e); }
    if len(n) < 256 {
        return err("RSA key must be at least 2048 bits");
    }
    let k = blank_key(a, kid);
    k.pem = pem;
    k.n = n;
    k.e = ex;
    k.can_sign = true;
    return ok(k);
}

// An RSA public key for RS256 or PS256, from its modulus and exponent
// (big-endian bytes, as a JWK's n and e decode to).
pub fn rsa_public_key(a: Alg, n: bytes, e: bytes, kid: str) -> result[Key, str] {
    if a != Alg.RS256 && a != Alg.PS256 {
        return err("rsa_public_key takes RS256 or PS256");
    }
    let m = n;
    let lead = 0;
    while lead < len(m) && m[lead] == 0 {
        lead += 1;
    }
    if len(m) - lead < 256 || len(m) - lead > 1024 {
        return err("RSA key must be 2048 to 8192 bits");
    }
    if len(e) < 1 || len(e) > 8 {
        return err("RSA exponent must be 1 to 8 bytes");
    }
    let k = blank_key(a, kid);
    k.n = m[lead..];
    k.e = e;
    return ok(k);
}

// An ES256 private key: a 32-byte P-256 scalar.
pub fn ec_private_key(scalar: bytes, kid: str) -> result[Key, str] {
    let rp = crypto.ecdsa_p256_public_key(scalar);
    guard let p = rp else let e = err_of(rp) { return err(e); }
    let k = blank_key(Alg.ES256, kid);
    k.private = scalar;
    k.public = p;
    k.can_sign = true;
    return ok(k);
}

// An ES256 public key from its coordinates (32 bytes each, as a JWK's x
// and y decode to).
pub fn ec_public_key(x: bytes, y: bytes, kid: str) -> result[Key, str] {
    if len(x) != 32 || len(y) != 32 {
        return err("P-256 coordinates must be 32 bytes each");
    }
    let point = b"\x04" + x + y;
    // Checked on the curve now, once, rather than at every verification.
    let probe = crypto.ecdsa_p256_verify_sha256(point, b"", strings.bytes_zero(64));
    if let _v = probe {
        let k = blank_key(Alg.ES256, kid);
        k.public = point;
        return ok(k);
    }
    return err(err_of(probe));
}

// An EdDSA (Ed25519) private key: the 32-byte seed.
pub fn ed25519_private_key(seed: bytes, kid: str) -> result[Key, str] {
    let rp = crypto.ed25519_public_key(seed);
    guard let p = rp else let e = err_of(rp) { return err(e); }
    let k = blank_key(Alg.EdDSA, kid);
    k.private = seed;
    k.public = p;
    k.can_sign = true;
    return ok(k);
}

// An EdDSA (Ed25519) public key: 32 bytes, as a JWK's x decodes to.
pub fn ed25519_public_key(public: bytes, kid: str) -> result[Key, str] {
    if len(public) != 32 {
        return err("Ed25519 public key must be 32 bytes");
    }
    let k = blank_key(Alg.EdDSA, kid);
    k.public = public;
    return ok(k);
}

// The public half of a key, safe to publish (for a JWKS): HMAC keys have
// none and are an error.
pub fn public_of(k: Key) -> result[Key, str] {
    if k.alg == Alg.HS256 || k.alg == Alg.HS384 || k.alg == Alg.HS512 {
        return err("an HMAC key has no public half");
    }
    let p = blank_key(k.alg, k.kid);
    p.public = k.public;
    p.n = k.n;
    p.e = k.e;
    return ok(p);
}

// ---- signing ----------------------------------------------------------------

// sign_with encodes typed claims as a compact JWS signed with key: the
// header is {"alg":...,"kid":...,"typ":"JWT"} (kid only when the key has
// one).
pub fn sign_with[T](claims: T, key: Key) -> result[str, str] {
    return sign_with_key_limits(claims, key, default_limits());
}

pub fn sign_with_key_limits[T](claims: T, key: Key, limits: Limits) -> result[str, str] {
    let valid_limits = check_limits(limits);
    guard let _l = valid_limits else let e = err_of(valid_limits) {
        return err(e);
    }
    if !key.can_sign {
        return err("jwt key cannot sign: it is a public key");
    }
    let header = "{\"alg\":\"" + alg_name(key.alg) + "\"";
    if key.kid != "" {
        header = header + ",\"kid\":" + json.encode(key.kid);
    }
    header = header + ",\"typ\":\"JWT\"}";
    let payload_json: str = json.encode(claims);
    if !strings.has_prefix(payload_json, "{") {
        return err("jwt claims must encode as a JSON object");
    }
    if len(payload_json) > limits.max_token_bytes {
        return err("jwt exceeds the configured token size limit");
    }
    let payload = to_bytes(payload_json);
    let field_check = count_claim_fields(payload, limits.max_claim_fields);
    guard let _f = field_check else let e = err_of(field_check) {
        return err(e);
    }
    let input = encoding.base64url_encode(to_bytes(header)) + "." +
                encoding.base64url_encode(payload);
    let rs = raw_signature(key, to_bytes(input));
    guard let sig = rs else let e = err_of(rs) {
        return err(e);
    }
    let token = input + "." + encoding.base64url_encode(sig);
    if len(token) > limits.max_token_bytes {
        return err("jwt exceeds the configured token size limit");
    }
    return ok(token);
}

fn raw_signature(key: Key, input: bytes) -> result[bytes, str] {
    if key.alg == Alg.HS256 {
        return ok(crypto.hmac_sha256(key.secret, input));
    }
    if key.alg == Alg.HS384 {
        return ok(crypto.hmac_sha384(key.secret, input));
    }
    if key.alg == Alg.HS512 {
        return ok(crypto.hmac_sha512(key.secret, input));
    }
    if key.alg == Alg.RS256 {
        return crypto.rsa_sign_sha256(key.pem, input);
    }
    if key.alg == Alg.PS256 {
        return crypto.rsa_sign_pss_sha256(key.pem, input);
    }
    if key.alg == Alg.ES256 {
        return crypto.ecdsa_p256_sign_sha256(key.private, input);
    }
    return crypto.ed25519_sign(key.private, input);
}

// ---- verification -------------------------------------------------------------

struct KeyedHeader {
    alg: str,
    typ: opt[str],
    kid: opt[str],
}

// verify_with checks a compact JWS against keys and decodes its claims
// into T. The header's alg must be one of the keys' algorithms, and when
// the header has a kid, a key with that kid (and that algorithm) is the
// only one tried; with no kid, each key of that algorithm is tried, at
// most 8. As with verify, the signature is checked before the claims are
// decoded, and expiry and audience policy stay with the caller (or use
// verify_id_token).
pub fn verify_with[T](token: str, keys: [Key]) -> result[T, str] {
    return verify_with_key_limits(token, keys, default_limits());
}

pub fn verify_with_key_limits[T](token: str, keys: [Key], limits: Limits) -> result[T, str] {
    let rp = verify_payload(token, keys, limits);
    guard let payload = rp else let e = err_of(rp) {
        return err(e);
    }
    let claims: result[T, str] = json.decode(payload);
    guard let value = claims else {
        return err("jwt claims do not match the requested type");
    }
    return ok(value);
}

let MAX_KEYS_TRIED = 8;

// The authenticated claims bytes of a token, checked against keys.
fn verify_payload(token: str, keys: [Key], limits: Limits) -> result[bytes, str] {
    let valid_limits = check_limits(limits);
    guard let _l = valid_limits else let e = err_of(valid_limits) {
        return err(e);
    }
    if len(token) > limits.max_token_bytes {
        return err("jwt exceeds the configured token size limit");
    }
    if strings.count(token, ".") != 2 {
        return err("jwt must have exactly three compact segments");
    }
    let first_dot = strings.find(token, ".");
    let second_dot = strings.rfind(token, ".");
    if first_dot <= 0 || second_dot <= first_dot + 1 || second_dot >= len(token) - 1 {
        return err("jwt has an empty compact segment");
    }
    let header_segment = strings.slice(token, 0, first_dot);
    let payload_segment = strings.slice(token, first_dot + 1, second_dot);
    let signature_segment = strings.slice(token, second_dot + 1, len(token));
    if len(header_segment) > MAX_HEADER_SEGMENT_BYTES {
        return err("jwt header exceeds the size limit");
    }
    let hr = decode_canonical(header_segment);
    guard let header_bytes = hr else {
        return err("invalid jwt header encoding");
    }
    if has_unsupported_header(header_bytes) {
        return err("jwt uses an unsupported protected header parameter");
    }
    let hd: result[KeyedHeader, str] = json.decode(header_bytes);
    guard let header = hd else {
        return err("invalid jwt header JSON");
    }
    // Candidates: keys of the header's algorithm, narrowed by kid.
    let candidates: [Key] = [];
    let alg_known = false;
    for k in keys {
        if alg_name(k.alg) != header.alg {
            continue;
        }
        alg_known = true;
        if let kid = header.kid {
            if k.kid != kid {
                continue;
            }
        }
        if len(candidates) < MAX_KEYS_TRIED {
            push(candidates, k);
        }
    }
    if !alg_known {
        return err("jwt algorithm is not accepted for these keys");
    }
    if len(candidates) == 0 {
        return err(ERR_UNKNOWN_KID);
    }
    let sr = decode_canonical(signature_segment);
    guard let signature = sr else {
        return err("invalid jwt signature encoding");
    }
    let input = to_bytes(strings.slice(token, 0, second_dot));
    let verified = false;
    for k in candidates {
        if signature_ok(k, input, signature) {
            verified = true;
            break;
        }
    }
    if !verified {
        return err("jwt signature is invalid");
    }
    let pr = decode_canonical(payload_segment);
    guard let payload = pr else {
        return err("invalid jwt claims encoding");
    }
    if !starts_json_object(payload) {
        return err("jwt claims must be a JSON object");
    }
    let field_check = check_claim_fields(payload, limits.max_claim_fields);
    guard let _f = field_check else let e = err_of(field_check) {
        return err(e);
    }
    return ok(payload);
}

fn signature_ok(k: Key, input: bytes, sig: bytes) -> bool {
    if k.alg == Alg.HS256 {
        return crypto.constant_time_eq(crypto.hmac_sha256(k.secret, input), sig);
    }
    if k.alg == Alg.HS384 {
        return crypto.constant_time_eq(crypto.hmac_sha384(k.secret, input), sig);
    }
    if k.alg == Alg.HS512 {
        return crypto.constant_time_eq(crypto.hmac_sha512(k.secret, input), sig);
    }
    if k.alg == Alg.RS256 {
        return crypto.rsa_verify_sha256(k.n, k.e, input, sig) ?? false;
    }
    if k.alg == Alg.PS256 {
        return crypto.rsa_verify_pss_sha256(k.n, k.e, input, sig) ?? false;
    }
    if k.alg == Alg.ES256 {
        return crypto.ecdsa_p256_verify_sha256(k.public, input, sig) ?? false;
    }
    return crypto.ed25519_verify(k.public, input, sig) ?? false;
}

// ---- JWK and JWKS (RFC 7517) --------------------------------------------------

struct Jwk {
    kty: str,
    kid: opt[str],
    alg: opt[str],
    use: opt[str],
    crv: opt[str],
    x: opt[str],
    y: opt[str],
    n: opt[str],
    e: opt[str],
    // private (d) and secret (k) members: present means refused
    d: opt[str],
    k: opt[str],
}

struct JwkSet {
    keys: [Jwk],
}

// A public key from a JWK (RSA, EC P-256 or OKP Ed25519). Its algorithm
// is the JWK's alg, or, when it has none, the one its type implies: RSA
// is RS256, P-256 is ES256, Ed25519 is EdDSA. Secret (oct) and private
// members are refused: a JWK read here is a published verification key.
pub fn key_from_jwk(text: str) -> result[Key, str] {
    let r: result[Jwk, str] = json.decode(text);
    guard let j = r else let e = err_of(r) {
        return err("invalid JWK: " + e);
    }
    return jwk_key(j);
}

fn jwk_b64(field: opt[str], name: str) -> result[bytes, str] {
    guard let v = field else {
        return err("JWK is missing " + name);
    }
    let r = decode_canonical(v);
    guard let b = r else {
        return err("JWK " + name + " is not canonical base64url");
    }
    return ok(b);
}

fn jwk_key(j: Jwk) -> result[Key, str] {
    if let _d = j.d {
        return err("JWK contains private key material");
    }
    if let _k = j.k {
        return err("JWK contains secret key material");
    }
    let kid = j.kid ?? "";
    let alg = j.alg ?? "";
    if j.kty == "RSA" {
        let a = Alg.RS256;
        if alg == "PS256" {
            a = Alg.PS256;
        } else if alg != "" && alg != "RS256" {
            return err("JWK alg " + alg + " is not supported for RSA");
        }
        let rn = jwk_b64(j.n, "n");
        guard let n = rn else let e = err_of(rn) { return err(e); }
        let re = jwk_b64(j.e, "e");
        guard let ex = re else let e = err_of(re) { return err(e); }
        return rsa_public_key(a, n, ex, kid);
    }
    if j.kty == "EC" {
        if (j.crv ?? "") != "P-256" {
            return err("JWK curve " + (j.crv ?? "(none)") + " is not supported");
        }
        if alg != "" && alg != "ES256" {
            return err("JWK alg " + alg + " is not supported for P-256");
        }
        let rx = jwk_b64(j.x, "x");
        guard let x = rx else let e = err_of(rx) { return err(e); }
        let ry = jwk_b64(j.y, "y");
        guard let y = ry else let e = err_of(ry) { return err(e); }
        return ec_public_key(x, y, kid);
    }
    if j.kty == "OKP" {
        if (j.crv ?? "") != "Ed25519" {
            return err("JWK curve " + (j.crv ?? "(none)") + " is not supported");
        }
        if alg != "" && alg != "EdDSA" {
            return err("JWK alg " + alg + " is not supported for Ed25519");
        }
        let rx = jwk_b64(j.x, "x");
        guard let x = rx else let e = err_of(rx) { return err(e); }
        return ed25519_public_key(x, kid);
    }
    return err("JWK key type " + j.kty + " is not supported");
}

// The verification keys of a JWK Set. Keys this package cannot use -- an
// encryption key ("use": "enc"), another curve or algorithm -- are
// skipped, so one exotic entry does not hide the rest; a set with no
// usable key at all is an error. Private members are refused outright.
pub fn parse_jwks(text: str) -> result[[Key], str] {
    if len(text) > 1048576 {
        return err("JWKS exceeds 1 MiB");
    }
    let r: result[JwkSet, str] = json.decode(text);
    guard let set = r else let e = err_of(r) {
        return err("invalid JWKS: " + e);
    }
    let keys: [Key] = [];
    for j in set.keys {
        if let _d = j.d {
            return err("JWKS contains private key material");
        }
        if let _k = j.k {
            return err("JWKS contains secret key material");
        }
        if (j.use ?? "sig") != "sig" {
            continue;
        }
        let k = jwk_key(j);
        if let key = k {
            push(keys, key);
        }
    }
    if len(keys) == 0 {
        return err("JWKS has no usable signing key");
    }
    return ok(keys);
}

// A key as a public JWK, for publishing in a JWKS. HMAC keys have no
// public form and are an error.
pub fn jwk_of(k: Key) -> result[str, str] {
    let p = public_of(k);
    guard let key = p else let e = err_of(p) {
        return err(e);
    }
    let out = "{";
    if key.alg == Alg.RS256 || key.alg == Alg.PS256 {
        out = out + "\"kty\":\"RSA\",\"n\":\"" + encoding.base64url_encode(key.n) +
              "\",\"e\":\"" + encoding.base64url_encode(key.e) + "\"";
    } else if key.alg == Alg.ES256 {
        out = out + "\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" +
              encoding.base64url_encode(key.public[1..33]) + "\",\"y\":\"" +
              encoding.base64url_encode(key.public[33..65]) + "\"";
    } else {
        out = out + "\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" +
              encoding.base64url_encode(key.public) + "\"";
    }
    out = out + ",\"alg\":\"" + alg_name(key.alg) + "\",\"use\":\"sig\"";
    if key.kid != "" {
        out = out + ",\"kid\":" + json.encode(key.kid);
    }
    return ok(out + "}");
}
