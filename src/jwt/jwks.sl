// A JWKS client: fetches a JWK Set over HTTPS, keeps it, and refreshes it
// when it expires or when a token names a kid it does not have -- at most
// once per min_interval, so a flood of tokens with made-up kids cannot
// make it hammer the issuer. One Jwks is shared by every task: lookups
// take its lock briefly, and a refetch holds it, so concurrent misses
// wait for one fetch instead of each starting their own.

import "httpc";
import "json";
import "strings";
import "time";

pub gc struct Jwks {
    url: str,
    client: httpc.Client,
    keys: [Key],
    // monotonic nanoseconds; 0 = never
    fetched_at: int,
    expires_at: int,
    last_attempt: int,
    max_age: int,
    min_interval: int,
    last_error: str,
    lock: mutex,
}

let SECOND = 1000000000;
let MAX_JWKS_BYTES = 1048576;

// A client for the JWK Set at url (https only), kept for an hour unless
// the response's Cache-Control: max-age says less, and refetched for an
// unknown kid at most every 30 seconds.
pub fn new_jwks(url: str) -> result[Jwks, str] {
    return new_jwks_with(url, 3600, 30);
}

// max_age_seconds caps how long a fetched set is used (a response's
// max-age may shorten it); min_interval_seconds is the least time between
// two fetches, whatever triggers them.
pub fn new_jwks_with(url: str, max_age_seconds: int, min_interval_seconds: int)
                     -> result[Jwks, str] {
    if !strings.has_prefix(url, "https://") {
        return err("JWKS URL must use https");
    }
    if max_age_seconds < 1 || max_age_seconds > 86400 * 7 {
        return err("JWKS max age must be 1 second to 7 days");
    }
    if min_interval_seconds < 1 || min_interval_seconds > max_age_seconds {
        return err("JWKS refresh interval must be 1 second up to the max age");
    }
    return ok(Jwks {
        url: url,
        client: httpc.new_client(),
        keys: [],
        fetched_at: 0,
        expires_at: 0,
        last_attempt: 0,
        max_age: max_age_seconds * SECOND,
        min_interval: min_interval_seconds * SECOND,
        last_error: "",
        lock: make_mutex()
    });
}

fn now_mono() -> int {
    return time.mono() as int;
}

// The current keys, fetching them first when there are none or they have
// expired (and a fetch is allowed). A failed refresh keeps the old keys:
// an issuer's brief outage should not log every user out.
pub fn jwks_keys(j: Jwks, deadline: until) -> result[[Key], str] {
    mutex_lock(j.lock);
    let now = now_mono();
    if (len(j.keys) == 0 || now >= j.expires_at) && now - j.last_attempt >= j.min_interval {
        refresh_locked(j, deadline);
    }
    let keys = j.keys;
    let e = j.last_error;
    mutex_unlock(j.lock);
    if len(keys) == 0 {
        if e == "" {
            return err("JWKS has not been fetched yet");
        }
        return err(e);
    }
    return ok(keys);
}

// Fetch now unless the last fetch was under min_interval ago. Returns
// whether keys were replaced. The caller holds j.lock.
fn refresh_locked(j: Jwks, deadline: until) -> bool {
    let now = now_mono();
    if j.last_attempt != 0 && now - j.last_attempt < j.min_interval {
        return false;
    }
    j.last_attempt = now;
    let r = httpc.client_get(j.client, j.url, deadline);
    guard let resp = r else let e = err_of(r) {
        j.last_error = "JWKS fetch failed: " + e;
        return false;
    }
    if resp.status != 200 {
        j.last_error = "JWKS fetch failed: HTTP " + to_str(resp.status);
        return false;
    }
    if len(resp.body) > MAX_JWKS_BYTES {
        j.last_error = "JWKS fetch failed: response over 1 MiB";
        return false;
    }
    let pr = parse_jwks(to_str(resp.body));
    guard let keys = pr else let e = err_of(pr) {
        j.last_error = e;
        return false;
    }
    let age = j.max_age;
    let cc = httpc.header(resp, "cache-control") ?? "";
    let ma = max_age_of(cc);
    if ma >= 0 && ma * SECOND < age {
        age = ma * SECOND;
    }
    if age < j.min_interval {
        age = j.min_interval;
    }
    j.keys = keys;
    j.fetched_at = now;
    j.expires_at = now + age;
    j.last_error = "";
    return true;
}

// The max-age directive of a Cache-Control value in seconds, or -1.
fn max_age_of(cc: str) -> int {
    let lower = strings.to_lower(cc);
    let at = strings.find(lower, "max-age=");
    if at < 0 {
        return -1;
    }
    let rest = to_bytes(strings.slice(lower, at + 8, len(lower)));
    let v = 0;
    let digits = 0;
    while digits < len(rest) && rest[digits] >= 48 && rest[digits] <= 57 && digits < 9 {
        v = v * 10 + (rest[digits] - 48);
        digits += 1;
    }
    if digits == 0 {
        return -1;
    }
    return v;
}

// Replace the keys by hand, as if fetched now: for tests, and for a set
// that arrives some other way (configuration, a sidecar).
pub fn jwks_set_keys(j: Jwks, keys: [Key]) {
    mutex_lock(j.lock);
    let now = now_mono();
    j.keys = keys;
    j.fetched_at = now;
    j.expires_at = now + j.max_age;
    j.last_attempt = now;
    j.last_error = "";
    mutex_unlock(j.lock);
}

// verify_jwks is verify_with against the set's keys. A token naming a kid
// the set lacks triggers one refetch (rate-limited) and one retry: that is
// how a key rotation at the issuer is picked up.
pub fn verify_jwks[T](token: str, j: Jwks, deadline: until) -> result[T, str] {
    let rp = jwks_payload(token, j, deadline, default_limits());
    guard let payload = rp else let e = err_of(rp) {
        return err(e);
    }
    let claims: result[T, str] = json.decode(payload);
    guard let value = claims else {
        return err("jwt claims do not match the requested type");
    }
    return ok(value);
}

fn jwks_payload(token: str, j: Jwks, deadline: until, limits: Limits) -> result[bytes, str] {
    let rk = jwks_keys(j, deadline);
    guard let keys = rk else let e = err_of(rk) {
        return err(e);
    }
    let first = verify_payload(token, keys, limits);
    if let p = first {
        return ok(p);
    }
    if err_of(first) != ERR_UNKNOWN_KID {
        return first;
    }
    mutex_lock(j.lock);
    let refreshed = refresh_locked(j, deadline);
    let fresh = j.keys;
    mutex_unlock(j.lock);
    if !refreshed {
        return first;
    }
    return verify_payload(token, fresh, limits);
}
