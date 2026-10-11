import "jwt";
import "time";

struct Claims {
    sub: str,
    exp: int,
    role: str,
}

fn write_samples(label: str, samples: [int]) {
    for i in 0..len(samples) {
        println(label + " " + to_str(samples[i]));
    }
}

let iterations = 1000;
let key: bytes = b"01234567890123456789012345678901";
let claims = Claims { sub: "user-7", exp: 2000000000, role: "reader" };
let signed: result[str, str] = jwt.sign(claims, key);
guard let token = signed else { panic("benchmark signing setup failed"); }
let warm_verify: result[Claims, str] = jwt.verify(token, key);
guard let _warm_claims = warm_verify else {
    panic("benchmark verification warmup failed");
}
println("T " + token);

let sign_samples: [int] = [];
let checksum = 0;
let sign_batch_start = time.mono();
for i in 0..iterations {
    let started = time.mono();
    let signed_value: result[str, str] = jwt.sign(claims, key);
    let finished = time.mono();
    guard let generated = signed_value else { panic("benchmark sign failed"); }
    checksum = checksum + len(generated);
    let elapsed: duration = finished - started;
    push(sign_samples, elapsed as int);
}
let sign_batch_elapsed: duration = time.mono() - sign_batch_start;

let verify_samples: [int] = [];
let verify_batch_start = time.mono();
for i in 0..iterations {
    let started = time.mono();
    let verified_value: result[Claims, str] = jwt.verify(token, key);
    let finished = time.mono();
    guard let checked = verified_value else { panic("benchmark verify failed"); }
    checksum = checksum + len(checked.sub) + checked.exp;
    let elapsed: duration = finished - started;
    push(verify_samples, elapsed as int);
}
let verify_batch_elapsed: duration = time.mono() - verify_batch_start;

println("B S " + to_str(sign_batch_elapsed as int));
write_samples("S", sign_samples);
println("B V " + to_str(verify_batch_elapsed as int));
write_samples("V", verify_samples);
println("C " + to_str(checksum));
