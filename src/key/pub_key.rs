#[cfg(feature = "ntrup1013")]
use crate::params::params1013::PUBLICKEYS_BYTES;
#[cfg(feature = "ntrup1277")]
use crate::params::params1277::PUBLICKEYS_BYTES;
#[cfg(feature = "ntrup653")]
use crate::params::params653::PUBLICKEYS_BYTES;
#[cfg(feature = "ntrup761")]
use crate::params::params761::PUBLICKEYS_BYTES;
#[cfg(feature = "ntrup857")]
use crate::params::params857::PUBLICKEYS_BYTES;
#[cfg(feature = "ntrup953")]
use crate::params::params953::PUBLICKEYS_BYTES;

use crate::{
    encode::rq,
    ntru::errors::NTRUErrors,
    poly::{errors::KemErrors, r3::R3, rq::Rq},
};

use super::priv_key::PrivKey;

pub type PubKey = Rq;

impl PubKey {
    /// Represents a public key in the context of a polynomial in the Fq field.
    ///
    /// A public key `PubKey` is formed as the result of a polynomial operation in the Fq field.
    /// It is computed as `h = (1/3 * fq) * g3`, where:
    /// - `h` is the public key.
    /// - `fq` is the entropy generated from random numbers in the field q.
    /// - `g3` is the entropy generated from random data in the field 3.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ntrulp::poly::rq::Rq;
    /// use ntrulp::poly::r3::R3;
    /// use ntrulp::key::pub_key::PubKey;
    /// use rand::RngCore;
    /// use ntrulp::random::{random_small, short_random};
    ///
    /// let mut rng = rand::thread_rng();
    /// // Create an Fq polynomial fq and a g3 polynomial g3
    /// let fq = Rq::from(short_random(&mut rng).unwrap());
    /// let g3 = R3::from(random_small(&mut rng));
    /// // Compute the public key
    /// let pub_key = PubKey::compute(&fq, &g3).unwrap();
    /// ```
    ///
    /// # Notes
    ///
    /// This implementation represents a public key formed by performing a polynomial operation
    /// in the Fq field, combining entropy from `fq` and `g3`.
    ///
    pub fn compute(f: &Rq, g: &R3) -> Result<Self, KemErrors> {
        let finv = f.recip::<3>()?;

        Ok(finv.mult_r3(&g))
    }

    /// Computes a public key from a given private key.
    ///
    /// # Arguments
    ///
    /// * `private_key`: The private key from which to derive the public key.
    ///
    /// # Returns
    ///
    /// Returns the corresponding public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ntrulp::poly::rq::Rq;
    /// use ntrulp::poly::r3::R3;
    /// use ntrulp::key::pub_key::PubKey;
    /// use ntrulp::key::priv_key::PrivKey;
    /// use rand::RngCore;
    /// use ntrulp::random::{random_small, short_random};
    ///
    /// let mut rng = rand::thread_rng();
    /// // Create an Fq polynomial fq and a g3 polynomial g3
    /// let fq = Rq::from(short_random(&mut rng).unwrap());
    /// let g3 = R3::from(random_small(&mut rng));
    /// let priv_key = PrivKey::compute(&fq, &g3).unwrap();
    /// let load_from_sk = PubKey::from_sk(&priv_key);
    /// ```
    ///
    /// # Panics
    ///
    /// The function may panic if the computation of the public key fails due to an invalid private key.
    ///
    pub fn from_sk(priv_key: &PrivKey) -> Result<Self, KemErrors> {
        let f = priv_key.0.rq_from_r3();
        let ginv = &priv_key.1;
        let g = ginv.recip()?;
        let finv = f.recip::<3>()?;
        let h = finv.mult_r3(&g);

        Ok(h)
    }

    /// Deserialize a byte array into a public key.
    ///
    /// # Arguments
    ///
    /// * `bytes`: A byte array containing the serialized public key.
    ///
    /// # Returns
    ///
    /// Returns the deserialized public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ntrulp::poly::rq::Rq;
    /// use ntrulp::poly::r3::R3;
    /// use ntrulp::key::pub_key::PubKey;
    /// use rand::RngCore;
    /// use ntrulp::random::{random_small, short_random};
    ///
    /// let mut rng = rand::thread_rng();
    /// // Create an Fq polynomial fq and a g3 polynomial g3
    /// let fq = Rq::from(short_random(&mut rng).unwrap());
    /// let g3 = R3::from(random_small(&mut rng));
    /// // Compute the public key
    /// let pub_key = PubKey::compute(&fq, &g3).unwrap();
    /// let imported_pub_key = PubKey::import(&pub_key.as_bytes()).unwrap();
    ///
    /// assert_eq!(pub_key.coeffs, imported_pub_key.coeffs);
    /// ```
    ///
    /// # Panics
    ///
    /// The function may panic if deserialization fails due to invalid or corrupted data.
    ///
    pub fn import(bytes: &[u8; PUBLICKEYS_BYTES]) -> Result<Self, NTRUErrors> {
        let coeffs = rq::decode(&bytes);
        let h = Rq::from(coeffs);

        Ok(h)
    }

    /// Converts a public key, represented as a polynomial in the field `Fq`, into a byte array.
    ///
    /// # Returns
    ///
    /// Returns a byte array representing the public key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ntrulp::poly::rq::Rq;
    /// use ntrulp::poly::r3::R3;
    /// use ntrulp::key::pub_key::PubKey;
    /// use rand::RngCore;
    /// use ntrulp::random::{random_small, short_random};
    ///
    /// let mut rng = rand::thread_rng();
    /// // Create an Fq polynomial fq and a g3 polynomial g3
    /// let fq = Rq::from(short_random(&mut rng).unwrap());
    /// let g3 = R3::from(random_small(&mut rng));
    /// // Compute the public key
    /// let pub_key = PubKey::compute(&fq, &g3).unwrap();
    /// let imported_pub_key = PubKey::import(&pub_key.as_bytes()).unwrap();
    ///
    /// assert_eq!(pub_key.coeffs, imported_pub_key.coeffs);
    /// ```
    ///
    pub fn as_bytes(&self) -> [u8; PUBLICKEYS_BYTES] {
        let h = self.coeffs;

        rq::encode(&h)
    }
}

#[cfg(test)]
mod test_pub_key {
    use super::*;
    use crate::random::{random_small, short_random};

    #[test]
    fn test_import_export() {
        let mut rng = rand::thread_rng();

        for _ in 0..1 {
            let f: Rq = Rq::from(short_random(&mut rng).unwrap());
            let g: R3 = R3::from(random_small(&mut rng));
            let pub_key = PubKey::compute(&f, &g).unwrap();
            let bytes = pub_key.as_bytes();
            let new_pub_key = match PubKey::import(&bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };

            assert_eq!(new_pub_key.coeffs, pub_key.coeffs);
        }
    }

    #[test]
    fn test_from_sk() {
        let mut rng = rand::thread_rng();
        let f: Rq = Rq::from(short_random(&mut rng).unwrap());
        let mut g: R3;

        let sk = loop {
            g = R3::from(random_small(&mut rng));

            match PrivKey::compute(&f, &g) {
                Ok(s) => break s,
                Err(_) => continue,
            };
        };
        let pub_key_from_entropy = PubKey::compute(&f, &g).unwrap();
        let pub_key_from_sk = PubKey::from_sk(&sk).unwrap();

        assert_eq!(pub_key_from_sk.coeffs, pub_key_from_entropy.coeffs);
    }
}
