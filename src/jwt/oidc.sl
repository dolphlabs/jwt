// OpenID Connect ID-token verification (OpenID Connect Core 1.0, 3.1.3.7):
// signature against the issuer's keys, then issuer, audience, authorized
// party, expiry, issue time, not-before and nonce, before the claims are
// handed back as the caller's type.

import "crypto";
import "json";
// What an ID token must satisfy. Build with id_token_rules, then set nonce
// when the login flow sent one.
pub struct IdTokenRules {
    issuer: str,
    audience: str,
    nonce: opt[str],
    leeway_seconds: int,
}

// Rules for tokens from issuer (its exact "iss", such as
// "https://accounts.google.com") meant for audience (your client id), with
// 60 seconds of clock leeway and no nonce check.
pub fn id_token_rules(issuer: str, audience: str) -> IdTokenRules {
    return IdTokenRules { issuer: issuer, audience: audience, nonce: none,
                          leeway_seconds: 60 };
}

// The standard claims, read beside the caller's type. aud is a string or a
// list of strings, so it is read both ways.
struct IdOne {
    iss: str,
    aud: str,
    exp: int,
    iat: int,
    nbf: opt[int],
    nonce: opt[str],
    azp: opt[str],
}

struct IdMany {
    iss: str,
    aud: [str],
    exp: int,
    iat: int,
    nbf: opt[int],
    nonce: opt[str],
    azp: opt[str],
}

// verify_id_token checks token against keys and rules at now (Unix
// seconds) and decodes its claims into T.
pub fn verify_id_token[T](token: str, keys: [Key], rules: IdTokenRules, now: int)
                          -> result[T, str] {
    let rp = verify_payload(token, keys, default_limits());
    guard let payload = rp else let e = err_of(rp) {
        return err(e);
    }
    return id_claims(payload, rules, now);
}

// verify_id_token against a JWKS client (keys fetched and rotated as in
// verify_jwks).
pub fn verify_id_token_jwks[T](token: str, j: Jwks, rules: IdTokenRules, now: int,
                               deadline: until) -> result[T, str] {
    let rp = jwks_payload(token, j, deadline, default_limits());
    guard let payload = rp else let e = err_of(rp) {
        return err(e);
    }
    return id_claims(payload, rules, now);
}

fn id_claims[T](payload: bytes, rules: IdTokenRules, now: int) -> result[T, str] {
    let iss = "";
    let exp = 0;
    let iat = 0;
    let nbf: opt[int] = none;
    let nonce: opt[str] = none;
    let azp: opt[str] = none;
    let aud_ok = false;
    let aud_count = 0;
    let one: result[IdOne, str] = json.decode(payload);
    if let c = one {
        iss = c.iss;
        exp = c.exp;
        iat = c.iat;
        nbf = c.nbf;
        nonce = c.nonce;
        azp = c.azp;
        aud_ok = c.aud == rules.audience;
        aud_count = 1;
    } else {
        let many: result[IdMany, str] = json.decode(payload);
        guard let c = many else {
            return err("id token lacks iss, aud, exp or iat, or has the wrong types");
        }
        iss = c.iss;
        exp = c.exp;
        iat = c.iat;
        nbf = c.nbf;
        nonce = c.nonce;
        azp = c.azp;
        aud_count = len(c.aud);
        for a in c.aud {
            if a == rules.audience {
                aud_ok = true;
            }
        }
    }
    if iss != rules.issuer {
        return err("id token issuer does not match");
    }
    if !aud_ok {
        return err("id token audience does not match");
    }
    // Several audiences: the token must say which one it was issued to.
    if let party = azp {
        if party != rules.audience {
            return err("id token authorized party does not match");
        }
    } else if aud_count > 1 {
        return err("id token has several audiences and no authorized party");
    }
    let leeway = rules.leeway_seconds;
    if now >= exp + leeway {
        return err("id token has expired");
    }
    if iat > now + leeway {
        return err("id token was issued in the future");
    }
    if let nb = nbf {
        if now + leeway < nb {
            return err("id token is not valid yet");
        }
    }
    if let want = rules.nonce {
        let got = nonce ?? "";
        if !crypto.constant_time_eq(to_bytes(got), to_bytes(want)) || got == "" {
            return err("id token nonce does not match");
        }
    }
    let claims: result[T, str] = json.decode(payload);
    guard let value = claims else {
        return err("id token claims do not match the requested type");
    }
    return ok(value);
}
