#[cfg(feature = "ntrup1013")]
use crate::params::params1013::P;
#[cfg(feature = "ntrup1277")]
use crate::params::params1277::P;
#[cfg(feature = "ntrup653")]
use crate::params::params653::P;
#[cfg(feature = "ntrup761")]
use crate::params::params761::P;
#[cfg(feature = "ntrup857")]
use crate::params::params857::P;
#[cfg(feature = "ntrup953")]
use crate::params::params953::P;

use super::{errors::KemErrors, f3, r3::R3};
use crate::{
    math::nums::{i16_negative_mask, i16_nonzero_mask},
    poly::fq,
};

#[derive(Debug)]
pub struct Rq {
    pub coeffs: [i16; P],
}

impl Rq {
    pub fn new() -> Self {
        Self { coeffs: [0i16; P] }
    }

    pub fn from(coeffs: [i16; P]) -> Self {
        Self { coeffs }
    }

    pub fn eq_one(&self) -> bool {
        for i in 1..self.coeffs.len() {
            if self.coeffs[i] != 0 {
                return false;
            }
        }

        self.coeffs[0] == 1
    }

    pub fn eq_zero(&self) -> bool {
        for c in self.coeffs {
            if c != 0 {
                return false;
            }
        }

        true
    }

    // h = f*g in the ring Rq
    pub fn mult_r3(&self, gq: &R3) -> Rq {
        let mut out = [0i16; P];
        let f = self.coeffs;
        let g = gq.coeffs;
        let mut fg = [0i16; P + P - 1];

        let quotient = |r: i16, f: i16, g: i8| {
            let value = r + f * g as i16;
            fq::freeze(value as i32)
        };

        for i in 0..P {
            let mut result = 0i16;

            for j in 0..=i {
                result = quotient(result, f[j], g[i - j]);
            }

            fg[i] = result;
        }

        for i in P..P + P - 1 {
            let mut result = 0i16;

            for j in (i - P + 1)..P {
                result = quotient(result, f[j], g[i - j]);
            }

            fg[i] = result;
        }

        for i in (P..=(P + P - 2)).rev() {
            fg[i - P] = fq::freeze((fg[i - P] + fg[i]) as i32);
            fg[i - P + 1] = fq::freeze((fg[i - P + 1] + fg[i]) as i32);
        }

        out[..P].copy_from_slice(&fg[..P]);

        Rq::from(out)
    }

    /// Computes the inverse of a polynomial in the Fq field.
    ///
    /// # Arguments
    ///
    /// - `ratio`: The coefficient multiplier of the polynomial.
    ///
    /// # Returns
    ///
    /// Returns the result, which represents the inverse of the polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use ntrulp::poly::rq::Rq;
    /// use rand::RngCore;
    /// use ntrulp::random::{random_small, short_random};
    ///
    /// const RATIO: i16 = 1;
    /// let mut rng = rand::thread_rng();
    /// let rq: Rq = Rq::from(short_random(&mut rng).unwrap());
    /// let out = rq.recip::<RATIO>().unwrap();
    /// let h = out.mult_r3(&rq.r3_from_rq());
    ///
    /// assert!(h.eq_one());
    /// ```
    ///
    /// # Notes
    ///
    /// This function calculates the inverse of a polynomial in the Fq field using the `ratio` coefficient as a multiplier for the polynomial.
    ///
    /// out = 1/(RATIO*F) in Rq
    pub fn recip<const RATIO: i16>(&self) -> Result<Rq, KemErrors> {
        let input = self.coeffs;
        let mut out = [0i16; P];
        let mut f = [0i16; P + 1];
        let mut g = [0i16; P + 1];
        let mut v = [0i16; P + 1];
        let mut r = [0i16; P + 1];
        let mut delta: i16;
        let mut swap: i16;
        let mut t: i16;
        let mut f0: i32;
        let mut g0: i32;
        let scale: i16;

        let quotient = |out: &mut [i16], f0: i32, g0: i32, fv: &[i16]| {
            for i in 0..P + 1 {
                let x = f0 * out[i] as i32 - g0 * fv[i] as i32;
                out[i] = fq::freeze(x);
            }
        };

        r[0] = fq::recip(RATIO);
        f[0] = 1;
        f[P - 1] = -1;
        f[P] = -1;

        for i in 0..P {
            g[P - 1 - i] = input[i] as i16;
        }

        g[P] = 0;
        delta = 1;

        for _ in 0..2 * P - 1 {
            for i in (1..=P).rev() {
                v[i] = v[i - 1];
            }
            v[0] = 0;

            swap = i16_negative_mask(-delta) & i16_nonzero_mask(g[0]);
            delta ^= swap & (delta ^ -delta);
            delta += 1;

            for i in 0..P + 1 {
                t = swap & (f[i] ^ g[i]);
                f[i] ^= t;
                g[i] ^= t;
                t = swap & (v[i] ^ r[i]);
                v[i] ^= t;
                r[i] ^= t;
            }

            f0 = f[0] as i32;
            g0 = g[0] as i32;

            quotient(&mut g, f0, g0, &f);
            quotient(&mut r, f0, g0, &v);

            for i in 0..P {
                g[i] = g[i + 1];
            }

            g[P] = 0;
        }

        scale = fq::recip(f[0]);

        for i in 0..P {
            let x = scale as i32 * (v[P - 1 - i] as i32);
            out[i] = fq::freeze(x) as i16;
        }

        if i16_nonzero_mask(delta) == 0 {
            Ok(Rq::from(out))
        } else {
            Err(KemErrors::NoSolutionRecip3)
        }
    }

    /// out = (num * poly) in Fq
    /// Multiplies a polynomial by a scalar integer value.
    ///
    /// This function multiplies each coefficient of the polynomial by the given integer `num`.
    ///
    /// # Arguments
    ///
    /// - `num`: The integer scalar value to multiply the polynomial by.
    ///
    /// # Returns
    ///
    /// Returns a new polynomial with coefficients multiplied by `num`.
    ///
    /// # Example
    ///
    /// ```
    /// #[cfg(feature = "ntrup1013")]
    /// use ntrulp::params::params1013::P;
    /// #[cfg(feature = "ntrup1277")]
    /// use ntrulp::params::params1277::P;
    /// #[cfg(feature = "ntrup653")]
    /// use ntrulp::params::params653::P;
    /// #[cfg(feature = "ntrup761")]
    /// use ntrulp::params::params761::P;
    /// #[cfg(feature = "ntrup857")]
    /// use ntrulp::params::params857::P;
    /// #[cfg(feature = "ntrup953")]
    /// use ntrulp::params::params953::P;
    /// use ntrulp::poly::rq::Rq;
    /// use rand::RngCore;
    ///
    /// let mut rng = rand::thread_rng();
    /// let rq: Rq = Rq::from([1_i16; P]);
    /// let out = rq.mult_int(3);
    ///
    /// for i in 0..P {
    ///     assert_eq!(out.coeffs[i], 3);
    /// }
    /// ```
    ///
    /// # Notes
    ///
    /// This function performs scalar multiplication of the polynomial by the provided integer value.
    ///
    pub fn mult_int(&self, num: i16) -> Rq {
        let mut out = [0i16; P];

        for i in 0..P {
            let x = (num * self.coeffs[i]) as i32;

            out[i] = fq::freeze(x);
        }

        Rq::from(out)
    }

    pub fn r3_from_rq(&self) -> R3 {
        let mut out = [0i8; P];

        for i in 0..P {
            out[i] = f3::freeze(self.coeffs[i])
        }

        R3::from(out)
    }
}

#[cfg(test)]
mod test_rq {
    use rand::RngCore;

    use super::*;
    use crate::random::short_random;

    #[test]
    fn test_mult_int() {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 5];
        rng.fill_bytes(&mut bytes);
        let num = bytes[2] as i16;
        let rq: Rq = Rq::from([1_i16; P]);
        let out = rq.mult_int(num);

        for i in 0..P {
            assert_eq!(out.coeffs[i], num);
        }
    }

    #[test]
    fn test_recip() {
        const RATIO: i16 = 1;

        let mut rng = rand::thread_rng();
        let rq: Rq = Rq::from(short_random(&mut rng).unwrap());
        let out = rq.recip::<RATIO>().unwrap();
        let h = out.mult_r3(&rq.r3_from_rq());

        assert!(h.eq_one());
    }
}
