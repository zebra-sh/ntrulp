use criterion::{criterion_group, criterion_main, Criterion};
use ntrulp::{poly::r3::R3, random::random_small};

fn encoder_benchmark(cb: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let r3 = R3::from(random_small(&mut rng));
    let r30 = R3::from(random_small(&mut rng));

    cb.bench_function("r3_recip", |b| {
        b.iter(|| {
            r3.recip().unwrap();
        });
    });
    cb.bench_function("rq_recip_3", |b| {
        b.iter(|| {
            r3.mult(&r30);
        });
    });
}

criterion_group!(benches, encoder_benchmark);
criterion_main!(benches);
