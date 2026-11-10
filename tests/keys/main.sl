// jwt with algorithm-bound keys: RS256, PS256, ES256, EdDSA and HS256/384/
// 512, JWK and JWKS parsing, kid selection, the key-confusion attack, OIDC
// ID-token checks and the JWKS client. The four "cli" tokens and the JWKS
// were produced outside slang (the openssl command-line tool and Python,
// keys generated for this test alone), so verifying them checks interop,
// not just a round trip through this package.

import "crypto";
import "encoding";
import "jwt";
import "strings";
import "time";

struct Claims {
    sub: str,
    exp: int,
    role: str,
}

struct Id {
    iss: str,
    sub: str,
    aud: str,
    exp: int,
    iat: int,
    nonce: opt[str],
}

struct IdMulti {
    iss: str,
    sub: str,
    aud: [str],
    azp: opt[str],
    exp: int,
    iat: int,
}

struct IdNbf {
    iss: str,
    aud: str,
    exp: int,
    iat: int,
    nbf: int,
}

fn check(name: str, ok: bool) {
    if ok {
        println("ok " + name);
    } else {
        println("FAIL " + name);
    }
}

fn key(r: result[jwt.Key, str]) -> jwt.Key {
    guard let k = r else let e = err_of(r) { panic(e); }
    return k;
}

fn token(r: result[str, str]) -> str {
    guard let t = r else let e = err_of(r) { panic(e); }
    return t;
}

fn why[T](r: result[T, str]) -> str {
    if let _v = r {
        return "(no error)";
    }
    return err_of(r);
}

fn role(r: result[Claims, str]) -> str {
    if let c = r {
        return c.role;
    }
    return "error: " + err_of(r);
}

fn b64(s: str) -> str {
    return encoding.base64url_encode(to_bytes(s));
}

// Typed wrappers: the claims type comes from the annotated result.
fn vw(t: str, keys: [jwt.Key]) -> result[Claims, str] {
    return jwt.verify_with(t, keys);
}
fn vid(t: str, keys: [jwt.Key], r: jwt.IdTokenRules, now: int) -> result[Id, str] {
    return jwt.verify_id_token(t, keys, r, now);
}
fn vidm(t: str, keys: [jwt.Key], r: jwt.IdTokenRules, now: int) -> result[IdMulti, str] {
    return jwt.verify_id_token(t, keys, r, now);
}
fn vidn(t: str, keys: [jwt.Key], r: jwt.IdTokenRules, now: int) -> result[IdNbf, str] {
    return jwt.verify_id_token(t, keys, r, now);
}
fn vidc(t: str, keys: [jwt.Key], r: jwt.IdTokenRules, now: int) -> result[Claims, str] {
    return jwt.verify_id_token(t, keys, r, now);
}
fn vj(t: str, j: jwt.Jwks, d: until) -> result[Claims, str] {
    return jwt.verify_jwks(t, j, d);
}
fn vijc(t: str, j: jwt.Jwks, r: jwt.IdTokenRules, now: int, d: until) -> result[Claims, str] {
    return jwt.verify_id_token_jwks(t, j, r, now, d);
}

// ---- RFC 8037 A.4: Ed25519 over a JWS signing input -------------------------
let rfc_d = encoding.base64url_decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A") ?? b"";
let rfc_x = encoding.base64url_decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo") ?? b"";
let rfc_sig = crypto.ed25519_sign(rfc_d, b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc") ?? b"";
check("rfc8037 A.4 signature", encoding.base64url_encode(rfc_sig) ==
      "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg");
check("rfc8037 A.4 public key", (crypto.ed25519_public_key(rfc_d) ?? b"") == rfc_x);

// ---- tokens made outside slang, through a JWKS ----------------------------------
let jwks_text = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"rsa1\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\"vWm0eWNcdcLpoUOKFq2dF0_3xWSj2f_FXS9KyzjB21m8rnUDGWKwsnmuW3FE74kFcqOwGfJheXDtwzLkHx7-TpHxBFBYDRioYHgwpbcH8ci0VBX0dptslq8iG6KyeQM2uROxV5hlPs1rw_07P0v-4l5cYpk1wwzu8J2SgtfbtZAVPI71hx3_XCAA7Qu1v9N7k2EppKxGR3P4O1eN_J-VL6tv9yeodL2emGjej4EV8LjG9jQUWF_ptUEYJclNxDSK7Bl7o4BQP0djckNaOQNKBXO5kaZMFPiAqV2hTyCvLqmPVIjaGovvPZKX7Qake6Xsm5uU43qKFIAQTQqeeNS44Q\",\"e\":\"AQAB\"},{\"kty\":\"RSA\",\"kid\":\"rsa-pss\",\"alg\":\"PS256\",\"n\":\"vWm0eWNcdcLpoUOKFq2dF0_3xWSj2f_FXS9KyzjB21m8rnUDGWKwsnmuW3FE74kFcqOwGfJheXDtwzLkHx7-TpHxBFBYDRioYHgwpbcH8ci0VBX0dptslq8iG6KyeQM2uROxV5hlPs1rw_07P0v-4l5cYpk1wwzu8J2SgtfbtZAVPI71hx3_XCAA7Qu1v9N7k2EppKxGR3P4O1eN_J-VL6tv9yeodL2emGjej4EV8LjG9jQUWF_ptUEYJclNxDSK7Bl7o4BQP0djckNaOQNKBXO5kaZMFPiAqV2hTyCvLqmPVIjaGovvPZKX7Qake6Xsm5uU43qKFIAQTQqeeNS44Q\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"ec1\",\"crv\":\"P-256\",\"x\":\"i35W0NMMHg-ix4pkcs9zVRlugZC-szQqPD2--vwAQ3I\",\"y\":\"bUG2fFAyt2eQ1vMFacRmsckXb4PN5I7MKKMImmIICsk\"},{\"kty\":\"OKP\",\"kid\":\"ed1\",\"crv\":\"Ed25519\",\"x\":\"xTH557B1bgYJfuvBuYE4sxMBU2yNwTmBxEZvwv2lHLA\"},{\"kty\":\"RSA\",\"kid\":\"enc1\",\"use\":\"enc\",\"n\":\"vWm0eWNcdcLpoUOKFq2dF0_3xWSj2f_FXS9KyzjB21m8rnUDGWKwsnmuW3FE74kFcqOwGfJheXDtwzLkHx7-TpHxBFBYDRioYHgwpbcH8ci0VBX0dptslq8iG6KyeQM2uROxV5hlPs1rw_07P0v-4l5cYpk1wwzu8J2SgtfbtZAVPI71hx3_XCAA7Qu1v9N7k2EppKxGR3P4O1eN_J-VL6tv9yeodL2emGjej4EV8LjG9jQUWF_ptUEYJclNxDSK7Bl7o4BQP0djckNaOQNKBXO5kaZMFPiAqV2hTyCvLqmPVIjaGovvPZKX7Qake6Xsm5uU43qKFIAQTQqeeNS44Q\",\"e\":\"AQAB\"},{\"kty\":\"EC\",\"kid\":\"p384\",\"crv\":\"P-384\",\"x\":\"AAAA\",\"y\":\"AAAA\"}]}";
let jr = jwt.parse_jwks(jwks_text);
guard let jwks_keys = jr else let e = err_of(jr) { panic(e); }
check("jwks keeps the 4 signing keys, skips enc and P-384", len(jwks_keys) == 4);
check("cli RS256 verifies", role(jwt.verify_with("eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYTEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.X_vCoiEfnsALLGWuEm12iDm9yKNGwIPLf9auAnktH_rWAZ-3yedP-lliazGDomvzo4mWT-neThs-gDJII6qX4Uk2uRh7qQGV6vgS1EdHOsW2jtOcPXj5BpGbCx4dxIHn1ApE6l-rg-fWOfhazKKLzuDSPfmS1y0uQlGpX7VbDYDYogDFVSwIolnBa88i9pgjs0HoMFyIA0NKmfP1yeeXEKWE3ZHZRUWo6JChA09lokTFoWQbYsnmAcFCk0FJT1nsl3vKexZN98AX6BPuQbMggAXZKFMn0tExjrOOYfYIygtG-atsQEcyG82IWxPQPlvNTzb8inW83V573cwj44bAZA", jwks_keys)) == "admin");
check("cli PS256 verifies", role(jwt.verify_with("eyJhbGciOiJQUzI1NiIsImtpZCI6InJzYS1wc3MiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.Fj49Bl8EPpwpKvAy-oi7FeS_aJ9TPHA9RKXwfitgJp-nrxYC09-zz1tBkRVRgNyOVWUzgPRvTpK_dZQCyGySkjxo_Tu1AkxwcR9flxKg94r6UhoptrTd0P-C_zbL2Jf_WYvW6ypNItB-1ENCyuSQvuNrB4G9iG8ckxqdgYkPZwOYz3YaBoIodU8ULTM1YimJoQDWJQMie3KLh_5BzGaCnESYNfGn0lu8QfMwnyxSAD4b3gRUJZ8mv-B2rL_vYgF346fY7Uh8ECeH0_F-ZoTLLQQFYppkNdGJ9xxbfofcvlORNWK_U3SSajPOsrbTXhYNJN5DNTbHDw9xP6IkQ9nyzA", jwks_keys)) == "admin");
check("cli ES256 verifies", role(jwt.verify_with("eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjMSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.iRvp1oCLGN4ctyM4xfOJ3Yrmh8ASF3ZCV_fD6U5G0CxWPPZvX-CXiehSxMDpmrzTR_Fvn-YISFmMl4UTbdGFMA", jwks_keys)) == "admin");
check("cli EdDSA verifies", role(jwt.verify_with("eyJhbGciOiJFZERTQSIsImtpZCI6ImVkMSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.WvheaHM0OuQ-FVHmCqZicklySDGgHm67S5Ju69VjlwcC-4JOsqIRp1GIT2eMKiXC83wmSW6h5pwnWHzlRpneCA", jwks_keys)) == "admin");

// ---- every algorithm round trips ------------------------------------------------
let claims = Claims { sub: "u1", exp: 4102444800, role: "reader" };
let hs256 = key(jwt.hmac_key(jwt.Alg.HS256, crypto.rand(32) ?? b"", "h256"));
let hs384 = key(jwt.hmac_key(jwt.Alg.HS384, crypto.rand(48) ?? b"", "h384"));
let hs512 = key(jwt.hmac_key(jwt.Alg.HS512, crypto.rand(64) ?? b"", ""));
let rsa = key(jwt.rsa_private_key(jwt.Alg.RS256, "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC9abR5Y1x1wumh\nQ4oWrZ0XT/fFZKPZ/8VdL0rLOMHbWbyudQMZYrCyea5bcUTviQVyo7AZ8mF5cO3D\nMuQfHv5OkfEEUFgNGKhgeDCltwfxyLRUFfR2m2yWryIborJ5Aza5E7FXmGU+zWvD\n/Ts/S/7iXlximTXDDO7wnZKC19u1kBU8jvWHHf9cIADtC7W/03uTYSmkrEZHc/g7\nV438n5Uvq2/3J6h0vZ6YaN6PgRXwuMb2NBRYX+m1QRglyU3ENIrsGXujgFA/R2Ny\nQ1o5A0oFc7mRpkwU+ICpXaFPIK8uqY9UiNoai+89kpftBqR7peybm5TjeooUgBBN\nCp541LjhAgMBAAECgf8fA2/JcGYd4gw0RhrAxoHc5KXCbE1nzw6XHhHhCdS0AGgk\nfdmZY89gFGG4Fz5yT2fU8s2ix00D1WRuJvxdxsqyPV3OlwPTy8sbVef2j5bSv/TG\nz9F3RNDtheolHD6cvH9Oo9V7F44m+lDq26EX0W7/zEjUMWyGw1dcORtZe9PoUPxE\nYYCFiGdm5Vk9/HuMo4P94uHLueoTOLhGf4M8HJl8GeD3WMi11p4p/s5nScAYKStG\nFbLRjCrF4tpwXUmj508Bxv4QrPH5SlIDeRrSLPoTCtsHFZtggfFitP2i0GSOntl2\nw8oKsnLgwZs+mLnQ5+usH35TrzsmYjKe8/SIz0ECgYEA6Q697kRJGv0cjKZoXLSz\ngsvRRzD+utf7cLOoX/b/dq5DM/NbSvpby+K58jDNAS6QDxDUimJziKdlo41Kc3jb\nxVoWfppzM0NYwwC71xxLzbSK7CZVofHrdB8IM4ILyiLsF9MU20gIXWVaEPWoqxEe\nrMe6WxZQkBiFKEFlDDnBBnECgYEA0A8UF6JM8wUifyOC7fJ2mthyoLQpdkFYMQcd\n5dsh5OoK6andKLUuc4Wo/09eJcM13ndq57A4zxCV+f122kQSVyqt/4Y+avVnfHz4\nSNK7xhzhFkeL5etiolBqisCIP+qTy3mhRbqtXHS993BGPBzfYPCfk66O5yWFwt1u\nI+HZcXECgYAdWxUDcSiANMem08MrgjtmS0QGIp7DbDcowAiCZftRuKuQXKPwMs7j\nRKDFZ+46quHMdANBlxsUaHl9+2sYVm3gUvOoaM3/9Ai3L115v/+wXoBtNHru1ikh\nTFNdIZFYmcOBUL48zLr5AK4ymq7vNU3W16WamZn2PJBxPKN8wb2VkQKBgEVZ0VOz\naLzUqFQCrUDNQhWJMmQ4yV0+mLv26FNWwKyCCtMqKKrKAcrF8bfwZ6xkrk8SNRM3\nXShAGg2zG+vTJt3hPxBeWe3jEPSg302+2JJHzAtWG96uoDkEXw8S8BeGBG+dglEw\n0VpxG2UgCnk9EoRIkJh0ZfPMQRLcJjtVq9oxAoGBAJ2yW45FRHsDx0q1jGRnGI8Y\nohofDH3HPsKeBV+ywD0LgnIOoy+d38cXPoi4ZNqicLLO/EwB+iCWfBexr8Jzc2AG\n2M8pS5fEgYuY2saHcOWzXBbKoE9Ls29ZRCp5i0z3dN/IuM1yJavuREkSniIp+pgb\nCd4IpOx2L/DycSrzccSn\n-----END PRIVATE KEY-----\n", "r1"));
let pss = key(jwt.rsa_private_key(jwt.Alg.PS256, "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC9abR5Y1x1wumh\nQ4oWrZ0XT/fFZKPZ/8VdL0rLOMHbWbyudQMZYrCyea5bcUTviQVyo7AZ8mF5cO3D\nMuQfHv5OkfEEUFgNGKhgeDCltwfxyLRUFfR2m2yWryIborJ5Aza5E7FXmGU+zWvD\n/Ts/S/7iXlximTXDDO7wnZKC19u1kBU8jvWHHf9cIADtC7W/03uTYSmkrEZHc/g7\nV438n5Uvq2/3J6h0vZ6YaN6PgRXwuMb2NBRYX+m1QRglyU3ENIrsGXujgFA/R2Ny\nQ1o5A0oFc7mRpkwU+ICpXaFPIK8uqY9UiNoai+89kpftBqR7peybm5TjeooUgBBN\nCp541LjhAgMBAAECgf8fA2/JcGYd4gw0RhrAxoHc5KXCbE1nzw6XHhHhCdS0AGgk\nfdmZY89gFGG4Fz5yT2fU8s2ix00D1WRuJvxdxsqyPV3OlwPTy8sbVef2j5bSv/TG\nz9F3RNDtheolHD6cvH9Oo9V7F44m+lDq26EX0W7/zEjUMWyGw1dcORtZe9PoUPxE\nYYCFiGdm5Vk9/HuMo4P94uHLueoTOLhGf4M8HJl8GeD3WMi11p4p/s5nScAYKStG\nFbLRjCrF4tpwXUmj508Bxv4QrPH5SlIDeRrSLPoTCtsHFZtggfFitP2i0GSOntl2\nw8oKsnLgwZs+mLnQ5+usH35TrzsmYjKe8/SIz0ECgYEA6Q697kRJGv0cjKZoXLSz\ngsvRRzD+utf7cLOoX/b/dq5DM/NbSvpby+K58jDNAS6QDxDUimJziKdlo41Kc3jb\nxVoWfppzM0NYwwC71xxLzbSK7CZVofHrdB8IM4ILyiLsF9MU20gIXWVaEPWoqxEe\nrMe6WxZQkBiFKEFlDDnBBnECgYEA0A8UF6JM8wUifyOC7fJ2mthyoLQpdkFYMQcd\n5dsh5OoK6andKLUuc4Wo/09eJcM13ndq57A4zxCV+f122kQSVyqt/4Y+avVnfHz4\nSNK7xhzhFkeL5etiolBqisCIP+qTy3mhRbqtXHS993BGPBzfYPCfk66O5yWFwt1u\nI+HZcXECgYAdWxUDcSiANMem08MrgjtmS0QGIp7DbDcowAiCZftRuKuQXKPwMs7j\nRKDFZ+46quHMdANBlxsUaHl9+2sYVm3gUvOoaM3/9Ai3L115v/+wXoBtNHru1ikh\nTFNdIZFYmcOBUL48zLr5AK4ymq7vNU3W16WamZn2PJBxPKN8wb2VkQKBgEVZ0VOz\naLzUqFQCrUDNQhWJMmQ4yV0+mLv26FNWwKyCCtMqKKrKAcrF8bfwZ6xkrk8SNRM3\nXShAGg2zG+vTJt3hPxBeWe3jEPSg302+2JJHzAtWG96uoDkEXw8S8BeGBG+dglEw\n0VpxG2UgCnk9EoRIkJh0ZfPMQRLcJjtVq9oxAoGBAJ2yW45FRHsDx0q1jGRnGI8Y\nohofDH3HPsKeBV+ywD0LgnIOoy+d38cXPoi4ZNqicLLO/EwB+iCWfBexr8Jzc2AG\n2M8pS5fEgYuY2saHcOWzXBbKoE9Ls29ZRCp5i0z3dN/IuM1yJavuREkSniIp+pgb\nCd4IpOx2L/DycSrzccSn\n-----END PRIVATE KEY-----\n", "p1"));
let ec = key(jwt.ec_private_key(crypto.ecdsa_p256_generate() ?? b"", "e1"));
let ed = key(jwt.ed25519_private_key(crypto.ed25519_generate() ?? b"", "d1"));
for k in [hs256, hs384, hs512, rsa, pss, ec, ed] {
    let t = token(jwt.sign_with(claims, k));
    let verify_keys: [jwt.Key] = [k];
    if let p = jwt.public_of(k) {
        verify_keys = [p];
    }
    check(jwt.alg_name(k.alg) + " round trip", role(jwt.verify_with(t, verify_keys)) == "reader");
}
check("an HS256 header names its kid", strings.contains(
      to_str(encoding.base64url_decode(strings.split(token(jwt.sign_with(claims, hs256)), ".")[0]) ?? b""),
      "\"kid\":\"h256\""));

// ---- published keys -------------------------------------------------------------
for k in [rsa, pss, ec, ed] {
    let text = jwt.jwk_of(k) ?? "";
    let back = jwt.key_from_jwk(text);
    guard let bk = back else let e = err_of(back) { panic(e); }
    check(jwt.alg_name(k.alg) + " jwk round trip", role(jwt.verify_with(token(jwt.sign_with(claims, k)), [bk])) == "reader");
    check(jwt.alg_name(k.alg) + " jwk has no private part", !strings.contains(text, "\"d\""));
}
println(why(jwt.jwk_of(hs256)));
println(why(jwt.key_from_jwk("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AA\",\"y\":\"AA\",\"d\":\"AA\"}")));
println(why(jwt.key_from_jwk("{\"kty\":\"oct\",\"k\":\"c2VjcmV0\"}")));
println(why(jwt.key_from_jwk("{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"AA\",\"y\":\"AA\"}")));
println(why(jwt.key_from_jwk("{\"kty\":\"RSA\",\"alg\":\"RS512\",\"n\":\"AA\",\"e\":\"AQAB\"}")));
println(why(jwt.key_from_jwk("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAA=\"}")));
println(why(jwt.parse_jwks("{\"keys\":[{\"kty\":\"RSA\",\"use\":\"enc\",\"n\":\"AA\",\"e\":\"AQAB\"}]}")));

// ---- algorithm binding and key selection --------------------------------------
let rsa_pub = key(jwt.public_of(rsa));
// The classic confusion: an HS256 token whose "secret" is the RSA public key.
let forged_key = key(jwt.hmac_key(jwt.Alg.HS256, rsa_pub.n, "r1"));
let forged = token(jwt.sign_with(claims, forged_key));
println(why(vw(forged, [rsa_pub])));
let ec_pub = key(jwt.public_of(ec));
let ec_other = key(jwt.public_of(key(jwt.ec_private_key(crypto.ecdsa_p256_generate() ?? b"", "e2"))));
let ec_token = token(jwt.sign_with(claims, ec));
check("kid picks the key", role(jwt.verify_with(ec_token, [ec_other, ec_pub])) == "reader");
println(why(vw(ec_token, [ec_other])));
let ec_nokid = key(jwt.ec_private_key(crypto.ecdsa_p256_generate() ?? b"", ""));
let nokid_token = token(jwt.sign_with(claims, ec_nokid));
let ec_nokid_pub = key(jwt.public_of(ec_nokid));
check("no kid: each key of the alg is tried", role(jwt.verify_with(nokid_token, [ec_other, ec_nokid_pub])) == "reader");
println(why(vw(nokid_token, [ec_other])));
println(why(jwt.sign_with(claims, ec_pub)));
println(why(jwt.hmac_key(jwt.Alg.HS384, crypto.rand(32) ?? b"", "")));
println(why(jwt.hmac_key(jwt.Alg.ES256, crypto.rand(32) ?? b"", "")));

// ---- tampering and hostile headers ------------------------------------------------
let parts = strings.split(ec_token, ".");
let other_payload = b64("{\"sub\":\"admin\",\"exp\":4102444800,\"role\":\"admin\"}");
println(why(vw(parts[0] + "." + other_payload + "." + parts[2], [ec_pub])));
let none_header = b64("{\"alg\":\"none\",\"kid\":\"e1\"}");
println(why(vw(none_header + "." + parts[1] + "." + parts[2], [ec_pub])));
let dup_kid = b64("{\"alg\":\"ES256\",\"kid\":\"e1\",\"kid\":\"e2\"}");
println(why(vw(dup_kid + "." + parts[1] + "." + parts[2], [ec_pub])));
let null_kid = b64("{\"alg\":\"ES256\",\"kid\":null}");
println(why(vw(null_kid + "." + parts[1] + "." + parts[2], [ec_pub])));
let escaped_kid = b64("{\"alg\":\"ES256\",\"kid\":\"e1\",\"\\u006bid\":\"e2\"}");
println(why(vw(escaped_kid + "." + parts[1] + "." + parts[2], [ec_pub])));

// ---- OpenID Connect ID tokens ---------------------------------------------------
let now = 1800000000;
let iss = "https://issuer.example";
let rules = jwt.id_token_rules(iss, "client-1");
let idt = token(jwt.sign_with(Id { iss: iss, sub: "u9", aud: "client-1", exp: now + 300,
                                   iat: now - 10, nonce: some("n-123") }, ec));
let ok_id = vid(idt, [ec_pub], rules, now);
check("id token verifies", (ok_id ?? Id { iss: "", sub: "", aud: "", exp: 0, iat: 0, nonce: none }).sub == "u9");
let with_nonce = rules;
with_nonce.nonce = some("n-123");
check("id token nonce matches", why(vid(idt, [ec_pub], with_nonce, now)) == "(no error)");
let bad_nonce = rules;
bad_nonce.nonce = some("n-999");
println(why(vid(idt, [ec_pub], bad_nonce, now)));
println(why(vid(idt, [ec_pub], jwt.id_token_rules("https://evil.example", "client-1"), now)));
println(why(vid(idt, [ec_pub], jwt.id_token_rules(iss, "client-2"), now)));
println(why(vid(idt, [ec_pub], rules, now + 300 + 60)));
check("id token inside the leeway", why(vid(idt, [ec_pub], rules, now + 300 + 59)) == "(no error)");
println(why(vid(idt, [ec_pub], rules, now - 10 - 61)));
let multi = token(jwt.sign_with(IdMulti { iss: iss, sub: "u9", aud: ["client-1", "client-2"],
                                          azp: some("client-1"), exp: now + 300, iat: now }, ec));
check("several audiences with azp", why(vidm(multi, [ec_pub], rules, now)) == "(no error)");
println(why(vidm(multi, [ec_pub], jwt.id_token_rules(iss, "client-2"), now)));
let multi_noazp = token(jwt.sign_with(IdMulti { iss: iss, sub: "u9", aud: ["client-1", "client-2"],
                                                azp: none, exp: now + 300, iat: now }, ec));
println(why(vidm(multi_noazp, [ec_pub], rules, now)));
let early = token(jwt.sign_with(IdNbf { iss: iss, aud: "client-1", exp: now + 300, iat: now,
                                        nbf: now + 120 }, ec));
println(why(vidn(early, [ec_pub], rules, now)));
let plain = token(jwt.sign_with(claims, ec));
println(why(vidc(plain, [ec_pub], rules, now)));

// ---- the JWKS client ---------------------------------------------------------------
println(why(jwt.new_jwks("http://issuer.example/jwks")));
println(why(jwt.new_jwks_with("https://issuer.example/jwks", 60, 120)));
let jc = jwt.new_jwks_with("https://127.0.0.1:1/jwks", 3600, 60);
guard let client = jc else let e = err_of(jc) { panic(e); }
let soon = until_of(time.mono() + 5000000000);
println(why(jwt.jwks_keys(client, soon)));
jwt.jwks_set_keys(client, jwks_keys);
check("verify_jwks with the cached set", role(jwt.verify_jwks("eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjMSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.iRvp1oCLGN4ctyM4xfOJ3Yrmh8ASF3ZCV_fD6U5G0CxWPPZvX-CXiehSxMDpmrzTR_Fvn-YISFmMl4UTbdGFMA", client, soon)) == "admin");
// An unknown kid refetches once (rate-limited: here inside min_interval,
// so no fetch), then reports the kid as unknown.
println(why(vj(ec_token, client, soon)));
check("id token through the jwks client", why(vijc("eyJhbGciOiJFUzI1NiIsImtpZCI6ImVjMSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGkiLCJleHAiOjQxMDI0NDQ4MDAsInJvbGUiOiJhZG1pbiJ9.iRvp1oCLGN4ctyM4xfOJ3Yrmh8ASF3ZCV_fD6U5G0CxWPPZvX-CXiehSxMDpmrzTR_Fvn-YISFmMl4UTbdGFMA", client,
      jwt.id_token_rules("https://nowhere.example", "x"), now, soon)) == "id token lacks iss, aud, exp or iat, or has the wrong types");
