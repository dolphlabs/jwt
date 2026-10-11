// Compact JWTs using HS256. Claims remain application-owned typed structs.
import "crypto";
import "encoding";
import "json";
import "strings";

pub let DEFAULT_MAX_TOKEN_BYTES = 16384;
pub let DEFAULT_MAX_CLAIM_FIELDS = 256;
let HARD_MAX_TOKEN_BYTES = 1048576;
let HARD_MAX_CLAIM_FIELDS = 4096;
let MAX_HEADER_SEGMENT_BYTES = 5462; // enough for a 4 KiB decoded header
let HS256_HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

pub struct Limits {
    max_token_bytes: int,
    max_claim_fields: int,
}

struct Header {
    alg: str,
    typ: opt[str],
}

// default_limits is a 16 KiB compact-token bound. Call new_limits to raise
// it when an application intentionally carries larger typed claims.
pub fn default_limits() -> Limits {
    return Limits {
        max_token_bytes: DEFAULT_MAX_TOKEN_BYTES,
        max_claim_fields: DEFAULT_MAX_CLAIM_FIELDS
    };
}

// Limits are capped at 1 MiB so a single untrusted bearer token cannot cause
// unbounded base64 or JSON allocations.
pub fn new_limits(max_token_bytes: int) -> result[Limits, str] {
    return new_limits_with_fields(max_token_bytes, DEFAULT_MAX_CLAIM_FIELDS);
}

// Claim fields are capped independently because many tiny fields can use
// more parser and map memory than one large claim value.
pub fn new_limits_with_fields(max_token_bytes: int, max_claim_fields: int)
                              -> result[Limits, str] {
    if max_token_bytes < 1 || max_token_bytes > HARD_MAX_TOKEN_BYTES {
        return err("jwt limits must be between 1 byte and 1 MiB");
    }
    if max_claim_fields < 1 || max_claim_fields > HARD_MAX_CLAIM_FIELDS {
        return err("jwt claim field limit must be between 1 and 4096");
    }
    return ok(Limits {
        max_token_bytes: max_token_bytes,
        max_claim_fields: max_claim_fields
    });
}

// sign encodes a JSON object of typed claims as an HS256 compact JWT. The
// shared key must be random secret bytes, at least 32 bytes long.
pub fn sign[T](claims: T, key: bytes) -> result[str, str] {
    return sign_with_limits(claims, key, default_limits());
}

pub fn sign_with_limits[T](claims: T, key: bytes, limits: Limits)
                           -> result[str, str] {
    let valid_limits = check_limits(limits);
    guard let _limits = valid_limits else let e = err_of(valid_limits) {
        return err(e);
    }
    let valid_key = check_key(key);
    guard let _key = valid_key else let e = err_of(valid_key) {
        return err(e);
    }

    let payload_json: str = json.encode(claims);
    if !strings.has_prefix(payload_json, "{") {
        return err("jwt claims must encode as a JSON object");
    }
    // Reject before base64 allocation when even the encoded payload cannot
    // fit inside this token's configured bound.
    let payload_size = len(payload_json);
    if payload_size > limits.max_token_bytes {
        return err("jwt exceeds the configured token size limit");
    }
    let payload_encoded_size = (payload_size / 3) * 4;
    if payload_size % 3 == 1 {
        payload_encoded_size = payload_encoded_size + 2;
    } else if payload_size % 3 == 2 {
        payload_encoded_size = payload_encoded_size + 3;
    }
    let fixed_size = len(HS256_HEADER) + 1 + 1 + 43;
    if payload_encoded_size + fixed_size > limits.max_token_bytes {
        return err("jwt exceeds the configured token size limit");
    }

    let payload = to_bytes(payload_json);
    let field_check = count_claim_fields(payload, limits.max_claim_fields);
    guard let _fields = field_check else let e = err_of(field_check) {
        return err(e);
    }
    let payload_segment = encoding.base64url_encode(payload);
    let signing_input = HS256_HEADER + "." + payload_segment;
    let mac = crypto.hmac_sha256(key, to_bytes(signing_input));
    let signature = encoding.base64url_encode(mac);
    let token = signing_input + "." + signature;
    return ok(token);
}

// verify requires HS256 regardless of the untrusted alg header. It checks the
// MAC before decoding the claims, then decodes them into the caller's type.
// It does not apply issuer, audience, expiry, authorization, or replay policy.
pub fn verify[T](token: str, key: bytes) -> result[T, str] {
    return verify_with_limits(token, key, default_limits());
}

pub fn verify_with_limits[T](token: str, key: bytes, limits: Limits)
                             -> result[T, str] {
    let valid_limits = check_limits(limits);
    guard let _limits = valid_limits else let e = err_of(valid_limits) {
        return err(e);
    }
    let valid_key = check_key(key);
    guard let _key = valid_key else let e = err_of(valid_key) {
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
    if first_dot <= 0 || second_dot <= first_dot + 1 ||
       second_dot >= len(token) - 1 {
        return err("jwt has an empty compact segment");
    }

    let header_segment = strings.slice(token, 0, first_dot);
    let payload_segment = strings.slice(token, first_dot + 1, second_dot);
    let signature_segment = strings.slice(token, second_dot + 1, len(token));
    if len(header_segment) > MAX_HEADER_SEGMENT_BYTES {
        return err("jwt header exceeds the size limit");
    }
    if len(signature_segment) != 43 {
        return err("invalid HS256 signature length");
    }

    let header_result = decode_canonical(header_segment);
    guard let header_bytes = header_result else {
        return err("invalid jwt header encoding");
    }
    let header_decoded: result[Header, str] = json.decode(header_bytes);
    guard let header = header_decoded else {
        return err("invalid jwt header JSON");
    }
    if header.alg != "HS256" {
        return err("jwt algorithm must be HS256");
    }
    if has_unsupported_header(header_bytes) {
        return err("jwt uses an unsupported protected header parameter");
    }

    let signature_result = decode_canonical(signature_segment);
    guard let signature = signature_result else {
        return err("invalid HS256 signature encoding");
    }
    if len(signature) != 32 {
        return err("invalid HS256 signature length");
    }

    let signing_input = strings.slice(token, 0, second_dot);
    let expected = crypto.hmac_sha256(key, to_bytes(signing_input));
    if !constant_time_equal(expected, signature) {
        return err("jwt signature is invalid");
    }

    // The payload may be large and attacker-controlled. Do not base64-decode
    // it or run the JSON decoder until its signature has been authenticated.
    let payload_result = decode_canonical(payload_segment);
    guard let payload = payload_result else {
        return err("invalid jwt claims encoding");
    }
    if !starts_json_object(payload) {
        return err("jwt claims must be a JSON object");
    }
    let field_check = check_claim_fields(payload, limits.max_claim_fields);
    guard let _fields = field_check else let e = err_of(field_check) {
        return err(e);
    }
    let claims: result[T, str] = json.decode(payload);
    guard let value = claims else {
        return err("jwt claims do not match the requested type");
    }
    return ok(value);
}

// valid_at checks NumericDate values in Unix seconds. Call it after verify;
// expiration is required so an unbounded token cannot pass by omission.
pub fn valid_at(exp: int, nbf: opt[int], now: int) -> bool {
    if now >= exp {
        return false;
    }
    if let not_before = nbf {
        if now < not_before {
            return false;
        }
    }
    return true;
}

fn check_limits(limits: Limits) -> result[bool, str] {
    if limits.max_token_bytes < 1 ||
       limits.max_token_bytes > HARD_MAX_TOKEN_BYTES {
        return err("jwt limits must be between 1 byte and 1 MiB");
    }
    if limits.max_claim_fields < 1 ||
       limits.max_claim_fields > HARD_MAX_CLAIM_FIELDS {
        return err("jwt claim field limit must be between 1 and 4096");
    }
    return ok(true);
}

fn check_key(key: bytes) -> result[bool, str] {
    if len(key) < 32 {
        return err("HS256 key must contain at least 32 random bytes");
    }
    if len(key) > 2147483647 {
        return err("HS256 key is too large");
    }
    return ok(true);
}

fn decode_canonical(segment: str) -> result[bytes, str] {
    if len(segment) == 0 {
        return err("empty base64url segment");
    }
    let decoded = encoding.base64url_decode(segment);
    guard let value = decoded else {
        return err("invalid base64url");
    }
    if encoding.base64url_encode(value) != segment {
        return err("non-canonical base64url");
    }
    return ok(value);
}

fn starts_json_object(raw: bytes) -> bool {
    let i = 0;
    while i < len(raw) &&
          (raw[i] == 32 || raw[i] == 9 || raw[i] == 10 || raw[i] == 13) {
        i = i + 1;
    }
    return i < len(raw) && raw[i] == 123;
}

fn constant_time_equal(a: bytes, b: bytes) -> bool {
    if len(a) != len(b) {
        return false;
    }
    let diff = 0;
    for i in 0..len(a) {
        diff = diff | (a[i] ^ b[i]);
    }
    return diff == 0;
}

// json.encode already emits unique keys; signing only needs this allocation-free
// top-level count scan, so it avoids the temporary key list used by verify.
fn count_claim_fields(raw: bytes, max_fields: int) -> result[bool, str] {
    let i = skip_json_ws(raw, 0);
    if i >= len(raw) || raw[i] != 123 {
        return err("jwt claims must be a JSON object");
    }
    i = i + 1;
    let count = 0;
    while i < len(raw) {
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        if raw[i] == 125 {
            break;
        }
        if raw[i] != 34 {
            return err("invalid jwt claims object");
        }
        i = skip_json_string(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        count = count + 1;
        if count > max_fields {
            return err("jwt claims exceed the configured field limit");
        }
        i = skip_json_ws(raw, i);
        if i >= len(raw) || raw[i] != 58 {
            return err("invalid jwt claims object");
        }
        i = skip_json_ws(raw, i + 1);
        i = skip_json_value(raw, i);
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        if raw[i] == 44 {
            i = i + 1;
        } else if raw[i] != 125 {
            return err("invalid jwt claims object");
        }
    }
    return ok(true);
}

// Verification checks uniqueness before decoding untrusted claims into T.
fn check_claim_fields(raw: bytes, max_fields: int) -> result[bool, str] {
    let i = skip_json_ws(raw, 0);
    if i >= len(raw) || raw[i] != 123 {
        return err("jwt claims must be a JSON object");
    }
    i = i + 1;
    let entries: [str] = [];
    let count = 0;
    while i < len(raw) {
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        if raw[i] == 125 {
            break;
        }
        if raw[i] != 34 {
            return err("invalid jwt claims object");
        }
        let key_start = i;
        i = skip_json_string(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        count = count + 1;
        if count > max_fields {
            return err("jwt claims exceed the configured field limit");
        }
        push(entries, strings.from_bytes(raw, key_start, i) + ":true");
        i = skip_json_ws(raw, i);
        if i >= len(raw) || raw[i] != 58 {
            return err("invalid jwt claims object");
        }
        i = skip_json_ws(raw, i + 1);
        i = skip_json_value(raw, i);
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return err("invalid jwt claims object");
        }
        if raw[i] == 44 {
            i = i + 1;
        } else if raw[i] != 125 {
            return err("invalid jwt claims object");
        }
    }

    let keys_json = "{" + strings.join(entries, ",") + "}";
    let keys_result: result[map[str]bool, str] = json.decode(keys_json);
    guard let keys = keys_result else {
        return err("invalid jwt claims keys");
    }
    if len(keys) != count {
        return err("jwt claims contain duplicate fields");
    }
    return ok(true);
}

// The typed JSON decoder maps both a missing opt field and an explicit null
// to none. Inspect top-level member names before accepting the protected
// header so `crit: null` and escaped spellings cannot bypass these checks.
fn has_unsupported_header(raw: bytes) -> bool {
    let i = skip_json_ws(raw, 0);
    let alg_seen = false;
    let typ_seen = false;
    if i >= len(raw) || raw[i] != 123 {
        return true;
    }
    i = i + 1;
    while i < len(raw) {
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return true;
        }
        if raw[i] == 125 {
            return !alg_seen;
        }
        if raw[i] != 34 {
            return true;
        }
        let is_alg = json_key_is(raw, i, 3);
        let is_typ = json_key_is(raw, i, 4);
        if json_key_is(raw, i, 1) || json_key_is(raw, i, 2) ||
           (is_alg && alg_seen) || (is_typ && typ_seen) {
            return true;
        }
        if is_alg { alg_seen = true; }
        if is_typ { typ_seen = true; }
        i = skip_json_string(raw, i);
        i = skip_json_ws(raw, i);
        if i >= len(raw) || raw[i] != 58 {
            return true;
        }
        i = skip_json_ws(raw, i + 1);
        if is_typ && i < len(raw) && raw[i] == 110 {
            return true;
        }
        i = skip_json_value(raw, i);
        i = skip_json_ws(raw, i);
        if i >= len(raw) {
            return true;
        }
        if raw[i] == 44 {
            i = i + 1;
        } else if raw[i] == 125 {
            return !alg_seen;
        } else {
            return true;
        }
    }
    return true;
}

fn json_key_is(raw: bytes, start: int, name: int) -> bool {
    let i = start + 1;
    let at = 0;
    let matches = true;
    let wanted_len = 4;
    if name == 2 || name == 3 || name == 4 { wanted_len = 3; }
    while i < len(raw) {
        let c = raw[i];
        if c == 34 {
            return matches && at == wanted_len;
        }
        if c == 92 {
            i = i + 1;
            if i >= len(raw) {
                return false;
            }
            if raw[i] == 117 {
                if i + 4 >= len(raw) {
                    return false;
                }
                let decoded = json_hex4(raw, i + 1);
                if decoded < 0 || decoded > 127 || at >= wanted_len ||
                   decoded != header_key_byte(name, at) {
                    matches = false;
                } else {
                    at = at + 1;
                }
                i = i + 4;
            } else {
                // The remaining JSON escapes decode to punctuation or
                // controls, none of which can match these ASCII names.
                matches = false;
            }
        } else if at >= wanted_len || c != header_key_byte(name, at) {
            matches = false;
        } else {
            at = at + 1;
        }
        i = i + 1;
    }
    return false;
}

fn header_key_byte(name: int, at: int) -> int {
    if name == 1 {
        if at == 0 { return 99; }
        if at == 1 { return 114; }
        if at == 2 { return 105; }
        return 116;
    }
    if name == 2 {
        if at == 0 { return 98; }
        if at == 1 { return 54; }
        return 52;
    }
    if name == 3 {
        if at == 0 { return 97; }
        if at == 1 { return 108; }
        return 103;
    }
    if at == 0 { return 116; }
    if at == 1 { return 121; }
    return 112;
}

fn json_hex4(raw: bytes, start: int) -> int {
    let value = 0;
    for j in 0..4 {
        let c = raw[start + j];
        let digit = -1;
        if c >= 48 && c <= 57 {
            digit = c - 48;
        } else if c >= 65 && c <= 70 {
            digit = c - 55;
        } else if c >= 97 && c <= 102 {
            digit = c - 87;
        } else {
            return -1;
        }
        value = value * 16 + digit;
    }
    return value;
}

fn skip_json_ws(raw: bytes, start: int) -> int {
    let i = start;
    while i < len(raw) &&
          (raw[i] == 32 || raw[i] == 9 || raw[i] == 10 || raw[i] == 13) {
        i = i + 1;
    }
    return i;
}

fn skip_json_string(raw: bytes, start: int) -> int {
    let i = start + 1;
    while i < len(raw) {
        if raw[i] == 92 {
            i = i + 2;
        } else if raw[i] == 34 {
            return i + 1;
        } else {
            i = i + 1;
        }
    }
    return len(raw);
}

fn skip_json_value(raw: bytes, start: int) -> int {
    let i = start;
    let depth = 0;
    let in_string = false;
    let escaped = false;
    while i < len(raw) {
        let c = raw[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == 92 {
                escaped = true;
            } else if c == 34 {
                in_string = false;
            }
        } else if c == 34 {
            in_string = true;
        } else if c == 123 || c == 91 {
            depth = depth + 1;
        } else if c == 125 || c == 93 {
            if depth == 0 {
                return i;
            }
            depth = depth - 1;
        } else if c == 44 && depth == 0 {
            return i;
        }
        i = i + 1;
    }
    return len(raw);
}
