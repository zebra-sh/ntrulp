#[cfg(feature = "ntrup1013")]
use crate::params::params1013::{P, RQ_BYTES};
#[cfg(feature = "ntrup1277")]
use crate::params::params1277::{P, RQ_BYTES};
#[cfg(feature = "ntrup653")]
use crate::params::params653::{P, RQ_BYTES};
#[cfg(feature = "ntrup761")]
use crate::params::params761::{P, RQ_BYTES};
#[cfg(feature = "ntrup857")]
use crate::params::params857::{P, RQ_BYTES};
#[cfg(feature = "ntrup953")]
use crate::params::params953::{P, RQ_BYTES};

pub fn encode(input: &[i16; P]) -> [u8; RQ_BYTES] {
    let mut bytes = [0u8; RQ_BYTES];
    let mut bytes_ptr: usize = 0;

    for i in 0..P {
        let b: [u8; 2] = input[i].to_be_bytes();

        bytes[bytes_ptr] = b[0];
        bytes_ptr += 1;
        bytes[bytes_ptr] = b[1];
        bytes_ptr += 1;
    }

    bytes
}

pub fn decode(input: &[u8; RQ_BYTES]) -> [i16; P] {
    let mut coeffs = [0i16; P];
    let mut coeffs_ptr: usize = 0;

    for i in (0..RQ_BYTES).step_by(2) {
        let bytes: [u8; 2] = [input[i], input[i + 1]];
        let value = i16::from_be_bytes(bytes);

        coeffs[coeffs_ptr] = value;
        coeffs_ptr += 1;
    }

    coeffs
}

#[cfg(test)]
mod tests_fq {
    use super::*;
    use crate::{poly::rq::Rq, random::short_random};

    #[test]
    fn test_encode_decode() {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let coeffs = short_random(&mut rng).unwrap();
            let rq = Rq::from(coeffs);

            let bytes = encode(&rq.coeffs);
            let res = decode(&bytes);

            assert_eq!(rq.coeffs, res);
        }
    }
}
