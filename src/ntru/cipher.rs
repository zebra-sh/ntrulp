#[cfg(feature = "ntrulpr1013")]
use crate::params::params1013::{P, W};
#[cfg(feature = "ntrulpr1277")]
use crate::params::params1277::{P, W};
#[cfg(feature = "ntrulpr653")]
use crate::params::params653::{P, W};
#[cfg(feature = "ntrulpr761")]
use crate::params::params761::{P, W};
#[cfg(feature = "ntrulpr857")]
use crate::params::params857::{P, W};
#[cfg(feature = "ntrulpr953")]
use crate::params::params953::{P, W};

use crate::key::priv_key::PrivKey;
use crate::key::pub_key::PubKey;
use crate::{
    math::nums::weightw_mask,
    poly::{f3::round, r3::R3, rq::Rq},
};

pub fn rq_decrypt(c: &Rq, priv_key: &PrivKey) -> R3 {
    let f = &priv_key.0;
    let ginv = &priv_key.1;
    let mut r = [0i8; P];
    let cf = c.mult_r3(&f);
    let cf3 = cf.mult_int(3);
    let e = cf3.r3_from_rq();
    let ev = e.mult(&ginv);
    let mask: i16;

    mask = weightw_mask(&ev.coeffs); // 0 if weight w, else -1

    for i in 0..W {
        r[i] = (((ev.coeffs[i] ^ 1) as i16 & !mask) ^ 1) as i8;
    }

    for i in W..P {
        r[i] = (ev.coeffs[i] as i16 & !mask) as i8;
    }

    R3::from(r)
}

pub fn r3_encrypt(r: &R3, pub_key: &PubKey) -> Rq {
    let mut hr = pub_key.mult_r3(&r);

    round(&mut hr.coeffs);

    hr
}

#[cfg(test)]
mod test_cipher {
    use super::*;
    use crate::random::CommonRandom;
    use crate::random::NTRURandom;

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut random: NTRURandom = NTRURandom::new();

        let r: R3 = Rq::from(random.short_random().unwrap()).r3_from_rq();
        let f: Rq = Rq::from(random.short_random().unwrap());
        let mut g: R3;
        let sk = loop {
            g = R3::from(random.random_small().unwrap());

            match PrivKey::compute(&f, &g) {
                Ok(s) => break s,
                Err(_) => continue,
            };
        };
        let pk = PubKey::compute(&f, &g).unwrap();
        let encrypted = r3_encrypt(&r, &pk);
        let decrypted = rq_decrypt(&encrypted, &sk);

        assert_eq!(decrypted.coeffs, r.coeffs);
    }
}
