use criterion::{criterion_group, criterion_main, Criterion};
use ntrulp::key::priv_key::PrivKey;
use ntrulp::key::pub_key::PubKey;
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::random::{random_small, short_random};

fn encoder_benchmark(cb: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let g: R3 = R3::from(random_small(&mut rng));
    let sk = PrivKey::compute(&f, &g).unwrap();

    cb.bench_function("gen_priv_key", |b| {
        b.iter(|| {
            PrivKey::compute(&f, &g).unwrap();
        });
    });
    cb.bench_function("gen_pub_key", |b| {
        b.iter(|| {
            PubKey::compute(&f, &g).unwrap();
        });
    });
    cb.bench_function("resolve_pub_key_from_priv_key", |b| {
        b.iter(|| {
            PubKey::from_sk(&sk).unwrap();
        });
    });
}

criterion_group!(benches, encoder_benchmark);
criterion_main!(benches);
