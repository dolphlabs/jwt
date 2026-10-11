import "crypto";
import "encoding";
import "jwt";
import "strings";

struct RfcClaims {
    iss: str,
    exp: int,
}

struct AccessClaims {
    sub: str,
    exp: int,
    nbf: opt[int],
    role: str,
}

fn is_err[T](r: result[T, str]) -> bool {
    if let _value = r { return false; }
    return true;
}

fn has_error[T](r: result[T, str], expected: str) -> bool {
    guard let _value = r else let message = err_of(r) {
        return message == expected;
    }
    return false;
}

fn require(ok: bool, what: str) {
    if !ok { panic("JWT test failed: " + what); }
}

fn fake_token(header: str) -> str {
    return encoding.base64url_encode(to_bytes(header)) + ".e30." +
           strings.repeat("A", 43);
}

fn signed_payload(payload: str, key: bytes) -> str {
    let header = encoding.base64url_encode(
        to_bytes("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    let body = encoding.base64url_encode(to_bytes(payload));
    let input = header + "." + body;
    let mac = crypto.hmac_sha256(key, to_bytes(input));
    return input + "." + encoding.base64url_encode(mac);
}

let rfc_key_result = encoding.base64url_decode(
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
guard let rfc_key = rfc_key_result else { panic("bad RFC fixture key"); }
let rfc_token =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
let rfc_claims: result[RfcClaims, str] = jwt.verify(rfc_token, rfc_key);
guard let rfc = rfc_claims else { panic("RFC HS256 vector was rejected"); }
require(rfc.iss == "joe" && rfc.exp == 1300819380, "RFC vector claims");
let signed_rfc: result[str, str] = jwt.sign(
    RfcClaims { iss: "joe", exp: 1300819380 }, rfc_key);
guard let issued_rfc = signed_rfc else {
    panic("RFC HS256 signing fixture failed");
}
require(issued_rfc ==
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODB9.vtajAuiiED5N1IlkJw6biq1sZzHqaV69C97gFipZlqk",
    "RFC-derived signing vector");
println("RFC vector ok");

let key: bytes = b"01234567890123456789012345678901";
let claims = AccessClaims {
    sub: "user-7",
    exp: 2000000000,
    nbf: some(1000000000),
    role: "reader"
};
let signed: result[str, str] = jwt.sign(claims, key);
guard let token = signed else { panic("sign failed"); }
let verified: result[AccessClaims, str] = jwt.verify(token, key);
guard let access = verified else { panic("verify failed"); }
require(access.sub == "user-7" && access.role == "reader", "typed claims");
require(jwt.valid_at(access.exp, access.nbf, 1500000000), "valid time");
require(jwt.valid_at(access.exp, access.nbf, 1000000000), "not-before boundary");
require(!jwt.valid_at(access.exp, access.nbf, 2000000000), "expiry boundary");
require(!jwt.valid_at(access.exp, access.nbf, 2100000000), "expiration");
require(!jwt.valid_at(access.exp, access.nbf, 900000000), "not-before");
println("typed sign and verify ok");

let first_dot = strings.find(token, ".");
let second_dot = strings.rfind(token, ".");
let payload_start = first_dot + 1;
let payload_first = strings.slice(token, payload_start, payload_start + 1);
let replacement = "A";
if payload_first == "A" { replacement = "B"; }
let bad_payload = replacement + strings.slice(token, payload_start + 1, second_dot);
let tampered = strings.slice(token, 0, payload_start) + bad_payload +
               "." + strings.slice(token, second_dot + 1, len(token));
let rejected_payload: result[AccessClaims, str] = jwt.verify(tampered, key);
require(has_error(rejected_payload, "jwt signature is invalid"),
        "authenticate before decoding modified payload");
let wrong_key: bytes = b"01234567890123456789012345678932";
let rejected_key: result[AccessClaims, str] = jwt.verify(token, wrong_key);
require(is_err(rejected_key), "wrong key");
let bad_signature_first = strings.slice(token, second_dot + 1, second_dot + 2);
let signature_replacement = "A";
if bad_signature_first == "A" { signature_replacement = "B"; }
let bad_signature = strings.slice(token, 0, second_dot + 1) +
    signature_replacement + strings.slice(token, second_dot + 2, len(token));
let rejected_signature: result[AccessClaims, str] = jwt.verify(bad_signature, key);
require(is_err(rejected_signature), "modified signature");
let malformed: result[AccessClaims, str] = jwt.verify("a.b", key);
require(is_err(malformed), "wrong segment count");
let extra_segment: result[AccessClaims, str] =
    jwt.verify("a.b.c.d", key);
require(is_err(extra_segment), "extra compact segment");
let malformed_json_token = signed_payload("{", key);
let malformed_json_result: result[AccessClaims, str] =
    jwt.verify(malformed_json_token, key);
require(is_err(malformed_json_result), "malformed signed claims JSON");
let nonobject_token = signed_payload("[]", key);
let nonobject_result: result[AccessClaims, str] = jwt.verify(nonobject_token, key);
require(is_err(nonobject_result), "non-object signed claims");
let invalid_typed_token = signed_payload("{\"sub\":7}", key);
let invalid_typed_result: result[AccessClaims, str] =
    jwt.verify(invalid_typed_token, key);
require(is_err(invalid_typed_result), "signed claims type mismatch");
let duplicate_exp_token = signed_payload(
    "{\"sub\":\"user-7\",\"exp\":2000000000,\"exp\":1,\"nbf\":null,\"role\":\"reader\"}",
    key);
let duplicate_exp_result: result[AccessClaims, str] =
    jwt.verify(duplicate_exp_token, key);
require(is_err(duplicate_exp_result), "duplicate expiration claim");
let escaped_duplicate_token = signed_payload(
    "{\"sub\":\"user-7\",\"\\u0073ub\":\"other\",\"exp\":2000000000,\"nbf\":null,\"role\":\"reader\"}",
    key);
let escaped_duplicate_result: result[AccessClaims, str] =
    jwt.verify(escaped_duplicate_token, key);
require(is_err(escaped_duplicate_result), "escaped duplicate claim");
let duplicate_role_token = signed_payload(
    "{\"sub\":\"user-7\",\"exp\":2000000000,\"nbf\":null,\"role\":\"reader\",\"role\":\"admin\"}",
    key);
let duplicate_role_result: result[AccessClaims, str] =
    jwt.verify(duplicate_role_token, key);
require(is_err(duplicate_role_result), "duplicate custom claim");
let too_many_fields_payload =
    "{\"sub\":\"user-7\",\"exp\":2000000000,\"nbf\":null,\"role\":\"reader\"" +
    strings.repeat(",\"x\":0", 253) + "}";
let too_many_fields_token = signed_payload(too_many_fields_payload, key);
let too_many_fields_result: result[AccessClaims, str] =
    jwt.verify(too_many_fields_token, key);
require(has_error(too_many_fields_result,
                  "jwt claims exceed the configured field limit"),
        "claim field limit before typed decoding");
println("tamper and malformed tokens rejected");

let none_token = fake_token("{\"alg\":\"none\"}");
let none_result: result[AccessClaims, str] = jwt.verify(none_token, key);
require(is_err(none_result), "none algorithm");
let unknown_token = fake_token("{\"alg\":\"HS384\"}");
let unknown_result: result[AccessClaims, str] = jwt.verify(unknown_token, key);
require(is_err(unknown_result), "unknown algorithm");
let duplicate_algorithm = fake_token(
    "{\"alg\":\"none\",\"alg\":\"HS256\"}");
let duplicate_algorithm_result: result[AccessClaims, str] =
    jwt.verify(duplicate_algorithm, key);
require(is_err(duplicate_algorithm_result), "duplicate algorithm");
let escaped_duplicate_algorithm = fake_token(
    "{\"alg\":\"HS256\",\"\\u0061lg\":\"HS256\"}");
let escaped_duplicate_algorithm_result: result[AccessClaims, str] =
    jwt.verify(escaped_duplicate_algorithm, key);
require(is_err(escaped_duplicate_algorithm_result),
        "escaped duplicate algorithm");
let escaped_duplicate_type = fake_token(
    "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"\\u0074yp\":\"JWT\"}");
let escaped_duplicate_type_result: result[AccessClaims, str] =
    jwt.verify(escaped_duplicate_type, key);
require(is_err(escaped_duplicate_type_result), "escaped duplicate type");
let critical_token = fake_token(
    "{\"alg\":\"HS256\",\"crit\":[\"private\"]}");
let critical_result: result[AccessClaims, str] =
    jwt.verify(critical_token, key);
require(is_err(critical_result), "critical header");
let unencoded_token = fake_token(
    "{\"alg\":\"HS256\",\"b64\":false}");
let unencoded_result: result[AccessClaims, str] =
    jwt.verify(unencoded_token, key);
require(is_err(unencoded_result), "unencoded payload header");
let null_critical_token = fake_token(
    "{\"alg\":\"HS256\",\"crit\":null}");
let null_critical_result: result[AccessClaims, str] =
    jwt.verify(null_critical_token, key);
require(is_err(null_critical_result), "null critical header");
let null_b64_token = fake_token(
    "{\"alg\":\"HS256\",\"b64\":null}");
let null_b64_result: result[AccessClaims, str] =
    jwt.verify(null_b64_token, key);
require(is_err(null_b64_result), "null b64 header");
let escaped_critical_token = fake_token(
    "{\"alg\":\"HS256\",\"c\\u0072it\":null}");
let escaped_critical_result: result[AccessClaims, str] =
    jwt.verify(escaped_critical_token, key);
require(is_err(escaped_critical_result), "escaped critical header");
let null_type_token = fake_token(
    "{\"alg\":\"HS256\",\"typ\":null}");
let null_type_result: result[AccessClaims, str] =
    jwt.verify(null_type_token, key);
require(is_err(null_type_result), "null type header");
let padded_header = strings.slice(token, 0, first_dot) + "=" +
    strings.slice(token, first_dot, len(token));
let padded_result: result[AccessClaims, str] =
    jwt.verify(padded_header, key);
require(is_err(padded_result), "padded segment");
println("algorithm and header restrictions ok");

let weak: bytes = b"short secret";
require(is_err(jwt.sign(claims, weak)), "short key");
let bad_limits = jwt.new_limits(1048577);
require(is_err(bad_limits), "hard size maximum");
let bad_field_limits = jwt.new_limits_with_fields(32768, 4097);
require(is_err(bad_field_limits), "hard claim field maximum");
let too_large: result[AccessClaims, str] = jwt.verify(
    strings.repeat("A", jwt.DEFAULT_MAX_TOKEN_BYTES + 1), key);
require(is_err(too_large), "default token size cap");
let custom_limits_result = jwt.new_limits(32768);
guard let custom_limits = custom_limits_result else {
    panic("valid custom limit rejected");
}
let tight_limits_result = jwt.new_limits_with_fields(32768, 3);
guard let tight_limits = tight_limits_result else {
    panic("valid claim field limit rejected");
}
require(is_err(jwt.sign_with_limits(claims, key, tight_limits)),
        "claim field limit");
let tight_verified: result[AccessClaims, str] =
    jwt.verify_with_limits(token, key, tight_limits);
require(is_err(tight_verified), "verification claim field limit");
let large_claims = AccessClaims {
    sub: strings.repeat("x", 16000),
    exp: 2000000000,
    nbf: none,
    role: "reader"
};
require(is_err(jwt.sign(large_claims, key)), "default signing cap");
let large_token_result = jwt.sign_with_limits(large_claims, key, custom_limits);
guard let large_token = large_token_result else {
    panic("custom signing limit rejected valid token");
}
let large_verified: result[AccessClaims, str] =
    jwt.verify_with_limits(large_token, key, custom_limits);
guard let large_access = large_verified else {
    panic("custom verification limit rejected valid token");
}
require(len(large_access.sub) == 16000, "large typed claim");
println("key and size limits ok");
