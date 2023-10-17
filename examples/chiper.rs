use std::sync::Arc;

use ntrulp::key::priv_key::PrivKey;
use ntrulp::key::pub_key::PubKey;
use ntrulp::ntru::cipher::{
    bytes_decrypt, bytes_encrypt, parallel_bytes_decrypt, parallel_bytes_encrypt, r3_encrypt,
    rq_decrypt,
};
use ntrulp::ntru::errors::NTRUErrors;
use ntrulp::poly::r3::R3;
use ntrulp::poly::rq::Rq;
use ntrulp::random::{random_small, short_random};
use rand::RngCore;

fn gen_keys<'a>() -> Result<(Arc<PrivKey>, Arc<PubKey>), NTRUErrors<'a>> {
    let mut rng = rand::thread_rng();
    let mut g: R3;
    let f: Rq = Rq::from(short_random(&mut rng).unwrap());
    let sk = loop {
        g = R3::from(random_small(&mut rng));

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).unwrap();

    Ok((Arc::new(sk), Arc::new(pk)))
}

fn main() {
    // create random generator.
    let mut rng = rand::thread_rng();

    let mut bytes = [0u8; 5];
    rng.fill_bytes(&mut bytes);

    let bytes = Arc::new(bytes.to_vec());

    let (sk, pk) = gen_keys().unwrap();

    // encryption for one thread only.
    let encrypted0 = bytes_encrypt(&mut rng, &bytes, &pk);

    // amount of CPU threads
    let num_threads = 4;

    // encryption with 4 threads
    let encrypted1 = Arc::new(parallel_bytes_encrypt(&mut rng, &bytes, &pk, num_threads).unwrap());

    // decryption with 4 threads
    let decrypted0 = parallel_bytes_decrypt(&encrypted1, &sk, num_threads).unwrap();

    // decryption one thread
    let decrypted1 = bytes_decrypt(&encrypted0, &sk).unwrap();

    assert_eq!(decrypted0, decrypted1);

    // This example is not required, only if you wnat works with stack
    // or make modify encode and decode algorithms
    //
    // generate a random poly in field F3.
    let r: R3 = Rq::from(short_random(&mut rng).unwrap()).r3_from_rq();

    // encryption r with pubKey in field Fq
    let cipher_rq = r3_encrypt(&r, &pk);
    // decrypt rq cipher
    let decrypted = rq_decrypt(&cipher_rq, &sk);

    assert_eq!(r.coeffs, decrypted.coeffs);
}
