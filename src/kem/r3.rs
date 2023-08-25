use super::{errors::KemErrors, f3, rq::Rq};
use crate::{
    kem::fq,
    math::nums::{i16_negative_mask, i16_nonzero_mask},
};

#[derive(Debug)]
pub struct R3<const P: usize, const Q: usize, const Q12: usize> {
    coeffs: [i8; P],
}

impl<const P: usize, const Q: usize, const Q12: usize> R3<P, Q, Q12> {
    pub fn new() -> Self {
        Self { coeffs: [0i8; P] }
    }

    pub fn from(coeffs: [i8; P]) -> Self {
        Self { coeffs }
    }

    /// Gets the slice of internal data.
    #[inline]
    pub fn get_coeffs(&self) -> &[i8; P] {
        &self.coeffs
    }

    // h = f*g in the ring R3
    pub fn r3_mult(&mut self, f: &[i8; P], g: &[i8; P]) {
        let mut fg = vec![0i8; P * 2 - 1];

        for i in 0..P {
            let mut r = 0i8;
            for j in 0..=i {
                let x = r + f[j] * g[i - j];

                r = f3::freeze(x as i16);
            }
            fg[i] = r;
        }
        for i in P..(P * 2 - 1) {
            let mut r = 0i8;
            for j in (i - P + 1)..P {
                let x = r + f[j] * g[i - j];
                r = f3::freeze(x as i16);
            }
            fg[i] = r;
        }

        for i in (P..P + P - 1).rev() {
            let x0 = fg[i - P] + fg[i];
            let x1 = fg[i - P + 1] + fg[i];

            fg[i - P] = f3::freeze(x0 as i16);
            fg[i - P + 1] = f3::freeze(x1 as i16);
        }

        self.coeffs[..P].clone_from_slice(&fg[..P]);
    }

    pub fn recip(&self) -> Result<R3<P, Q, Q12>, KemErrors> {
        let input = self.coeffs;
        let mut out = [0i8; P];
        let mut f = vec![0; P + 1];
        let mut g = vec![0; P + 1];
        let mut v = vec![0; P + 1];
        let mut r = vec![0; P + 1];
        let mut delta: i8;
        let mut sign: i8;
        let mut swap: i8;
        let mut t: i8;

        for i in 0..P + 1 {
            v[i] = 0;
        }
        for i in 0..P + 1 {
            r[i] = 0;
        }
        r[0] = 1;
        for i in 0..P {
            f[i] = 0;
        }
        f[0] = 1;
        f[P - 1] = -1;
        f[P] = -1;
        for i in 0..P {
            g[P - 1 - i] = input[i];
        }
        g[P] = 0;

        delta = 1;

        for _ in 0..2 * P - 1 {
            for i in (1..=P).rev() {
                v[i] = v[i - 1];
            }
            v[0] = 0;

            sign = -g[0] * f[0];
            swap = (i16_negative_mask(-delta as i16) & i16_nonzero_mask(g[0] as i16)) as i8;
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

            for i in 0..P + 1 {
                let x = g[i] + sign * f[i];
                g[i] = f3::freeze(x as i16);
            }
            for i in 0..P + 1 {
                let x = r[i] + sign * v[i];
                r[i] = f3::freeze(x as i16);
            }

            for i in 0..P {
                g[i] = g[i + 1];
            }
            g[P] = 0;
        }

        sign = f[0];
        for i in 0..P {
            out[i] = (sign * v[P - 1 - i]) as i8;
        }

        if i16_nonzero_mask(delta as i16) == 0 {
            Ok(R3::from(out))
        } else {
            Err(KemErrors::R3NoSolutionRecip)
        }
    }
}

#[cfg(test)]
mod test_r3 {
    use super::*;

    #[test]
    fn test_r3_mult() {
        const P: usize = 761;
        let f: [i8; P] = [
            1, 0, -1, 0, 1, -1, 0, 0, -1, 0, -1, 1, -1, -1, 0, 1, 1, 0, 0, 0, 0, -1, 0, -1, 0, 1,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, -1, 1, 0, 0, 0, -1, 0, 0, 1, 1, 1, -1, 1, 1, 1, 1,
            0, 0, 1, -1, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, -1, -1, -1, 0,
            0, 1, 0, -1, 1, 1, -1, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, -1, 0, -1, 0, -1, 1, 1, 0, 0,
            1, -1, 0, 1, 0, -1, 0, -1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, -1, 0, 1, 0, 0, 1, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 1, 0, 0, -1, 0, 0, -1, 0, 0, 1, 0, 1,
            0, 0, 0, -1, 1, 0, -1, 1, 0, 0, 1, 0, 1, -1, 0, 0, 1, 0, 1, -1, 1, 0, 1, 0, -1, 1, 0,
            0, -1, 0, 0, 0, 0, 0, 1, -1, -1, 0, -1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 0, 1, -1, 0,
            0, 0, -1, 0, -1, 1, 1, -1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, -1,
            0, 0, -1, 1, 1, 0, 0, 1, 0, 1, 1, -1, -1, 0, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, -1,
            0, 1, 1, -1, -1, -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, -1, -1, 0, -1, 0, -1, -1,
            0, 0, 1, 0, 1, 0, -1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, -1, 0, 0, 0, 0, 1, 0, 0, -1, 0,
            0, -1, -1, 0, 0, 0, 1, 0, 1, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0,
            0, 0, 1, -1, 0, 0, 0, -1, 1, 1, 1, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0,
            -1, 0, 1, 0, 0, 1, -1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1, 0,
            0, 0, -1, -1, 0, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1,
            0, 0, 1, -1, -1, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, -1, -1, 0, 0, 0, 0, -1,
            -1, -1, 0, 1, 0, 1, -1, 0, -1, 0, -1, -1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1,
            1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 1, -1, -1, 0, -1, 0, 1, 0, -1, 0,
            0, 0, 0, 0, 1, -1, 0, 0, -1, 1, 0, 1, 0, 0, 1, -1, 0, 0, 0, 1, 0, 0, 0, 0, -1, 1, 0, 0,
            0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, -1, 1, 0, 1, 0, 0, 1, -1, 1, 0, 1,
            1, -1, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, -1, 0, 0, 0,
            1, -1, 0, -1, 1, 0, 0, 1, 0, -1, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, -1, -1, 0, 0, 0, 0, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
            -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, -1, 0, -1, 1, 1, 0, 0, 1, 0, 1, -1, -1, 0, 1,
            -1, -1, 0, 0, 0, 0, -1, 1, 0, 0, -1, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 1, -1, 1, 0,
            0, 0, 1, 1, 1, 0, 0, -1, 0, 0, -1, 0, 0, 0, 1, -1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0,
        ];
        let g: [i8; P] = [
            -1, 1, -1, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, -1,
            -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1,
            -1, 0, -1, -1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, -1,
            0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0,
            0, -1, 1, 1, -1, 0, -1, -1, 0, 1, 0, 0, -1, -1, 1, 1, 0, -1, 0, 0, -1, 1, 0, -1, 0, 1,
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0,
            1, 0, 1, 1, -1, 0, 1, 0, -1, 1, 0, 0, 0, 1, 1, 0, 1, -1, 1, 0, 1, -1, 0, 0, 0, -1, 1,
            0, 1, 1, -1, 0, 0, 1, 0, 0, -1, -1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0,
            -1, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 1, 0, 1, -1, 0, 0, 0, 1, 0, 0, 1,
            -1, 1, -1, 0, 0, -1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 1, 1, 0, 0, -1, 1,
            0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, -1, 0, 0, 0, 0, 0, 1, 0, -1,
            1, 0, -1, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, -1, -1, 0, 1, 1, 1, -1, 0, 0, 0, -1, -1, 1,
            0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, 0, -1, 0, 1, 1,
            0, -1, -1, 0, 0, 1, 0, 1, -1, -1, 0, 1, 0, 0, 0, 1, 0, 0, -1, -1, -1, 0, -1, 1, -1, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, -1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
            0, -1, 1, 0, 0, -1, 0, 0, 0, -1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0,
            -1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, -1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 1, 1, 0, -1, 1, 0, 0, 0, 1, 1, 1, -1, -1, -1, 0, 0, 0, 1, 0, 1, -1,
            0, 0, -1, 1, -1, 0, 1, 0, 1, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 1,
            0, 0, 1, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, -1, 1, 0, 0, 0, 1, 0, 1,
            -1, 0, 1, 0, 0, 0, 0, 1, -1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
            1, 0, 0, 0, 0, -1, 0, 1, 0, 0, -1, -1, 0, 0, 1, -1, 1, -1, -1, 1, 0, 1, -1, -1, 0, 0,
            0, 1, -1, -1, 1, 0, 1, -1, 1, 0, 0, 0, 0, -1, 0, 0, 0, -1, 1, 1, 0, 0, 0, 1, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 1, 0, -1, 0, 0, 0, 1, -1, 0, -1, 0, -1, 0, 0, -1, 0, 0,
            1, -1, 0, 0, 1, 0, 0, 0, 1, -1, 0, -1, 0, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 0,
            0, 0, 1, 1, 1, -1, -1, -1, 0, 0, 0, 0, 1, -1, 1, 0, 0, 0, 0, 0, 1, 0, -1, 0, 1, -1, 0,
            0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 1,
        ];
        let mut h: R3<P, 1, 1> = R3::new();

        h.r3_mult(&f, &g);

        assert_eq!(
            h.coeffs,
            [
                -1, 1, 1, 0, 0, 1, -1, 1, 0, 1, 0, 1, 0, 1, 1, -1, 0, 0, 0, 1, 0, 1, -1, 0, -1, -1,
                0, 0, 0, 0, -1, -1, 0, 1, 0, 1, -1, -1, 1, 0, -1, -1, 1, 0, 0, -1, 1, 1, 1, -1, 1,
                1, 0, 1, -1, -1, 0, 1, 1, -1, -1, -1, 0, -1, 0, -1, 1, 1, -1, 0, 0, 0, -1, 0, 0,
                -1, -1, 0, -1, 1, 1, 1, -1, 0, -1, -1, -1, 1, -1, 0, -1, 0, 1, 1, -1, 0, -1, 0, 0,
                0, -1, 0, -1, -1, -1, -1, 0, -1, -1, 1, 0, -1, 0, 1, 1, 0, 0, 1, 0, 0, -1, 0, 1,
                -1, -1, -1, 0, -1, 1, -1, 0, 1, 1, 1, 0, -1, 1, -1, -1, 0, -1, 1, 1, 1, 1, -1, 1,
                -1, 1, 0, 1, 1, 1, -1, 1, 1, 0, -1, 1, -1, 0, 1, -1, -1, 0, 0, 1, -1, -1, -1, 1, 0,
                0, -1, -1, 0, 0, 0, 0, -1, -1, 0, 1, -1, -1, 0, 1, 1, 0, 1, 1, -1, 0, 0, 1, 1, -1,
                0, 0, 1, 0, 0, 1, -1, -1, 1, -1, -1, -1, 1, -1, -1, 1, 1, -1, -1, -1, 1, 0, 1, 0,
                0, 1, 1, 1, 0, 1, 0, 0, -1, 0, -1, 1, 1, -1, -1, 0, 0, 0, -1, 1, -1, 1, 0, 0, -1,
                0, 0, 0, -1, -1, 0, 0, -1, -1, -1, -1, -1, -1, -1, 1, 0, 0, 0, -1, 0, -1, 0, 1, 1,
                0, -1, -1, 0, 1, 1, 0, 0, 1, -1, 0, 0, -1, 0, 0, -1, 1, 1, -1, -1, 0, -1, 1, 0, 0,
                0, 1, 0, -1, 1, -1, 1, -1, 0, 0, 1, 0, -1, 1, -1, -1, -1, -1, -1, -1, 1, -1, -1,
                -1, -1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, -1, -1, 1, -1, 1, -1, 0, 0, 1, 1, 1, 1,
                0, 0, 1, 0, -1, -1, -1, -1, 0, -1, 1, -1, -1, 0, -1, 0, 0, 0, -1, -1, 0, -1, 0, -1,
                0, 0, -1, 1, 1, 1, -1, -1, 0, 0, 0, -1, -1, 0, 0, 1, 0, -1, 1, -1, -1, 1, 0, 0, 1,
                0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 1, 0, 1, 0, -1, -1, 0, 1, 1, 1, 0, 1, -1, -1,
                -1, 1, 0, 1, -1, 1, 0, 0, 0, 1, 0, -1, -1, -1, 0, 0, 1, 1, -1, 0, 0, 1, 1, 1, 1,
                -1, 0, -1, -1, -1, 0, 1, 0, 1, -1, 0, -1, 0, -1, 1, -1, 0, -1, 0, -1, 1, 0, 0, 1,
                -1, 1, -1, 0, 0, -1, 0, -1, 1, 0, -1, -1, 0, 0, -1, 0, 0, 1, -1, 1, 0, 1, -1, 0, 0,
                1, 1, 0, 0, -1, 1, -1, 0, -1, 0, 1, 1, 0, 0, 1, 0, -1, -1, 1, 1, 0, 0, 1, 1, 1, 1,
                -1, 1, 1, -1, -1, -1, 1, 1, 1, 1, 1, 1, 1, -1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, -1,
                -1, -1, 1, 1, 0, -1, -1, 1, 1, -1, 0, 1, -1, 1, 0, 0, 0, 1, 1, -1, 0, 1, 1, 1, 1,
                1, 1, -1, 1, 0, 1, 0, -1, 1, -1, 1, -1, 1, -1, 1, 0, 0, -1, 0, -1, 1, 1, -1, 1, -1,
                0, 1, 0, -1, 1, 0, 0, -1, 1, 1, 0, 1, -1, 0, 1, -1, 1, -1, 1, 1, -1, 0, 1, -1, -1,
                1, 0, -1, 0, 1, 0, 0, 0, -1, -1, 0, 0, 0, 1, 1, 1, 1, -1, 1, 1, 1, -1, 1, -1, 1, 1,
                0, -1, -1, 0, -1, -1, 0, 0, 0, 0, -1, 0, -1, 1, 0, -1, 0, 0, -1, -1, -1, 1, -1, 1,
                -1, -1, 0, -1, 0, 1, 0, -1, 1, -1, 1, 0, 0, -1, 0, -1, -1, 1, 1, 0, 0, -1, -1, 0,
                0, 0, 1, -1, 0, -1, -1, -1, 0, -1, -1, -1, 1, 1, 0, 0, 0, 0, -1, -1, 1, 0, 1, 0,
                -1, -1, 0, 0, 1, 0, 1, 0, 0, 0, -1, -1, 0, 1, 0, 0, -1, 1, 1, 0, 0, -1, 0, 0, 1,
                -1, 0, -1, 0, 0, -1, 1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 0, 1, -1, 1
            ]
        );
    }

    #[test]
    fn test_recip() {
        const P: usize = 761;
        const Q: usize = 4591;
        const Q12: usize = (Q - 1) / 2;

        let r3: R3<P, Q, Q12> = R3::from([
            0, -1, -1, 0, 0, -1, 0, -1, -1, 0, -1, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 1, 0, -1, -1,
            -1, 0, 0, 0, 1, 0, 1, 1, -1, -1, 0, -1, 1, 1, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 1,
            -1, 0, 0, 0, 0, -1, 0, 1, -1, -1, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, -1,
            0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 1, 0, -1, 0, -1, 1, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0,
            0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0,
            -1, 0, -1, 1, 0, 0, 0, -1, 0, -1, 0, 0, 0, -1, -1, 0, 1, 0, -1, 1, 0, -1, 0, 0, 0, 0,
            1, 0, 0, 0, 0, -1, -1, 1, 0, -1, -1, 0, -1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            1, 0, 0, 0, 1, -1, 1, 0, 0, 0, -1, 0, 0, 0, 1, 0, -1, -1, 0, 1, 0, 0, 0, 1, -1, -1, 1,
            -1, 1, -1, 1, 0, -1, 1, 0, 0, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 1,
            0, 0, 0, -1, 0, 0, 0, 0, 1, 1, -1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0,
            0, 0, -1, 1, 0, 0, -1, -1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
            0, 1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0,
            0, 1, 0, 0, 0, 0, -1, 1, 0, 1, -1, 0, 0, 1, -1, 0, 1, 0, 0, 0, -1, 1, 0, 0, 0, -1, 0,
            1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, -1, 0, 0, -1, 1, 0, 0, 1, 0, 0, -1, -1, 1, -1, -1, 1,
            1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, -1, 1, 1, 1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 1, 1,
            0, 0, -1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0,
            0, 0, 1, -1, -1, 0, 0, 0, 1, 0, 0, -1, 1, -1, 0, -1, -1, 0, 0, 1, 0, 0, 0, 0, -1, -1,
            -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, 1, 1, 0,
            0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 1, -1, -1, 0, 1, 0,
            0, 0, 0, -1, 0, -1, 0, 0, 1, 0, -1, 1, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 1, 0,
            0, 0, 0, 0, 1, 0, 1, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, -1, 1, 0, 0, -1, -1, 0, -1, 0, 1,
            0, -1, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 1, -1, 0, 1, 0,
            -1, 1, 1, 0, -1, -1, 1, -1, 0, 0, 0, -1, 1, 1, -1, 0, -1, 1, 1, 0, 0, -1, -1, 0, 0, 0,
            1, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, -1, 0, -1, 1, 0, 1, -1, 0, 0, -1, 0, 0, 0, 0,
            1, 0, 1, 0, 1, 1, 0, 0, 0, -1, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0,
            0, 1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, -1, -1, 0, 0, 0, 1, -1, 0, 0, 0, 1, 1, 0, 1,
            0, -1, 1, -1, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1,
            -1, -1, 1, -1, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0,
            0, 0,
        ]);

        let out = r3.recip().unwrap();

        assert_eq!(
            out.get_coeffs(),
            &[
                1, 0, -1, 0, 0, 0, 0, 0, -1, -1, 1, 0, 1, 1, -1, 0, 0, 1, -1, -1, -1, -1, -1, -1,
                -1, -1, 1, -1, 0, 0, -1, -1, -1, 0, 1, -1, 1, 0, 0, 1, -1, -1, -1, -1, 0, 1, 0, -1,
                0, 1, -1, 1, -1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, -1, -1, 1, -1, -1, 0, -1, 1, -1, 0,
                -1, -1, -1, -1, 0, 0, -1, -1, 0, 0, 1, 1, 1, 1, -1, 1, -1, 1, 1, -1, -1, 1, -1, -1,
                1, 0, 1, -1, 1, 0, 1, 0, 0, 1, -1, 0, 1, 1, 0, 0, 0, -1, 0, -1, 1, 1, 0, -1, 1, 1,
                0, 1, -1, 1, -1, -1, -1, 0, 1, 0, 0, 1, 1, 0, 0, -1, -1, 0, 0, 1, 1, 1, -1, -1, 1,
                1, 0, 1, 1, -1, -1, 0, -1, -1, 0, -1, 0, 0, 1, -1, 1, -1, 0, 0, 1, 0, -1, 0, 0, -1,
                1, -1, 1, 0, 0, 0, 1, 1, 1, 0, -1, 0, -1, -1, 1, 1, 1, 1, 1, -1, 0, -1, -1, 0, -1,
                -1, 0, 0, -1, -1, 0, -1, -1, 0, -1, 0, -1, -1, 0, -1, -1, 1, 0, 1, -1, -1, 0, -1,
                1, 1, -1, 0, 1, 1, 1, 1, 1, 0, 0, 0, -1, -1, 1, 0, 0, 1, 0, -1, -1, -1, 0, -1, 1,
                -1, -1, 1, -1, -1, -1, 1, -1, 0, 1, -1, 1, 0, 0, 0, -1, 1, -1, 1, 1, 0, 1, 0, -1,
                0, 1, 1, -1, 0, 1, 0, 1, 1, 0, 1, 0, 0, -1, 1, 1, 1, 1, 0, -1, 1, 0, -1, 0, 0, 1,
                1, 0, 0, 0, 1, 0, 1, 1, -1, 1, -1, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0, -1, 1, 1, -1,
                0, 1, 0, 1, 0, 0, -1, -1, 0, 0, -1, 0, 1, 1, 1, 0, 1, 1, 0, -1, 1, -1, 1, -1, -1,
                0, 0, 1, -1, 0, -1, -1, -1, -1, 0, -1, -1, 0, 0, 1, 1, 0, 1, -1, 1, 1, 1, 0, 0, 0,
                -1, 1, 1, -1, 1, 1, -1, 1, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, -1, 1, 1,
                0, 1, -1, 0, -1, 0, 1, 1, -1, 0, 1, 0, -1, -1, 1, 1, 1, -1, 0, 0, -1, 0, 0, 0, 1,
                0, 1, -1, -1, -1, -1, -1, 0, 1, 1, -1, -1, 1, 0, 1, 0, -1, 1, -1, 1, 1, 0, 0, 0, 1,
                0, 0, -1, 0, -1, -1, 1, -1, 1, -1, -1, 0, -1, 1, 0, -1, 1, 0, 1, 0, 1, -1, 0, -1,
                -1, -1, 0, -1, 1, 0, -1, 1, 0, -1, 0, 0, 0, -1, -1, 0, -1, 0, 1, 0, 0, -1, 1, -1,
                0, 1, -1, 0, -1, 1, 0, -1, 1, 1, 0, 1, -1, 1, -1, -1, 1, 1, -1, 1, 1, 0, 0, 0, -1,
                0, -1, 1, 0, 1, -1, -1, -1, 0, 1, 0, 1, -1, 0, 1, -1, 0, 0, 1, -1, 1, 1, 1, -1, 1,
                -1, 1, 0, 1, 1, 0, 0, -1, 0, -1, 1, 1, 1, 1, 0, 1, 0, -1, -1, 0, 0, 1, 1, -1, 1, 0,
                -1, -1, 0, 1, 0, -1, 0, 1, 1, 1, 1, 0, -1, 1, 1, 1, -1, 1, 1, 0, -1, 1, -1, 0, 1,
                1, 0, 0, -1, -1, 0, 1, -1, 1, 1, 0, 1, 0, -1, -1, 0, 1, 1, -1, -1, -1, -1, 0, 1, 1,
                0, 0, -1, 0, 0, 0, 0, 1, -1, 1, 0, 0, 1, -1, 1, -1, 0, 1, -1, 0, -1, -1, 0, 1, 1,
                1, 0, 1, 1, -1, -1, -1, -1, -1, 1, -1, 1, 0, 1, 0, -1, 0, -1, -1, 0, 0, 0, 1, -1,
                0, -1, 0, 0, -1, 0, 0, 1, 1, -1, 1, 0, 1, 1, 0, -1, 0, 1, -1, 0, 1, -1, -1, -1, 0,
                1, 0, 0, 0, 1, 0, 1, -1, -1, -1, 1, -1, 1, 1, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, 0, -1,
                1, 0, 1, 0, 0, 1, -1, 0, 1, 1, 1, 1, 0, -1, 1, -1, 0, -1, -1, 1, 1, 0, 1, 0, -1, 1,
                0, -1, 1, 1, -1, 0, 0, 1, -1, 0, -1, 0, 0
            ]
        );
    }
}
