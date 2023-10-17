#[cfg(feature = "ntrup1013")]
use crate::params::params1013::{P, R3_BYTES, RQ_BYTES, W};
#[cfg(feature = "ntrup1277")]
use crate::params::params1277::{P, R3_BYTES, RQ_BYTES, W};
#[cfg(feature = "ntrup653")]
use crate::params::params653::{P, R3_BYTES, RQ_BYTES, W};
#[cfg(feature = "ntrup761")]
use crate::params::params761::{P, R3_BYTES, RQ_BYTES, W};
#[cfg(feature = "ntrup857")]
use crate::params::params857::{P, R3_BYTES, RQ_BYTES, W};
#[cfg(feature = "ntrup953")]
use crate::params::params953::{P, R3_BYTES, RQ_BYTES, W};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::encode::{r3, rq};
use crate::key::priv_key::PrivKey;
use crate::key::pub_key::PubKey;
use crate::random::NTRURandom;
use crate::{
    math::nums::weightw_mask,
    poly::{f3::round, r3::R3, rq::Rq},
};

use super::errors::NTRUErrors;

fn usize_vec_to_bytes(list: &[usize]) -> Vec<u8> {
    list.iter()
        .flat_map(|&x| x.to_ne_bytes().to_vec())
        .collect()
}

fn byte_to_usize_vec(list: &[u8]) -> Vec<usize> {
    list.chunks_exact(std::mem::size_of::<usize>())
        .map(|chunk| {
            let mut bytes = [0; std::mem::size_of::<usize>()];
            bytes.copy_from_slice(chunk);
            usize::from_ne_bytes(bytes)
        })
        .collect()
}

fn unpack_bytes<'a>(bytes: &[u8]) -> Result<(Vec<u8>, Vec<usize>, u64), NTRUErrors<'a>> {
    let bytes_len = bytes.len();
    let seed_bytes: [u8; 8] = match &bytes[bytes_len - 8..].try_into() {
        Ok(v) => *v,
        Err(_) => return Err(NTRUErrors::SliceError("incorrect or damaged cipher bytes")),
    };
    let size_bytes_len: [u8; 8] = match &bytes[bytes_len - 16..bytes_len - 8].try_into() {
        Ok(v) => *v,
        Err(_) => return Err(NTRUErrors::SliceError("incorrect or damaged cipher bytes")),
    };
    let size_len = usize::from_ne_bytes(size_bytes_len);
    let seed = u64::from_ne_bytes(seed_bytes);

    let size_bytes = &bytes[bytes_len - size_len - 16..(bytes_len - 16)];
    let size = byte_to_usize_vec(size_bytes);

    let bytes_data = &bytes[..bytes_len - size_len - 16];

    Ok((bytes_data.to_vec(), size, seed))
}

fn pack_bytes(mut bytes: Vec<u8>, size: Vec<usize>, seed: u64) -> Vec<u8> {
    let size_bytes = usize_vec_to_bytes(&size);
    let size_len = size_bytes.len().to_ne_bytes();
    let seed_bytes = seed.to_ne_bytes();

    bytes.extend(size_bytes);
    bytes.extend(size_len);
    bytes.extend(seed_bytes);

    bytes
}

/// Decrypts a polynomial in the Fq field using a private key.
///
/// # Arguments
///
/// - `c`: The ciphertext polynomial to be decrypted.
/// - `priv_key`: The private key used for decryption.
///
/// # Returns
///
/// Returns the decrypted polynomial as a result of applying the private key to the ciphertext.
///
/// # Example
///
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::ntru::cipher::rq_decrypt;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate the ciphertext polynomial c and the private key
/// let c = Rq::from(random.short_random().unwrap());
/// let priv_key = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break s,
///         Err(_) => continue,
///     };
/// };
///
/// // Decrypt the ciphertext polynomial
/// let decrypted_poly = rq_decrypt(&c, &priv_key);
/// ```
///
/// # Notes
///
/// This function decrypts a ciphertext polynomial `c` using a private key `priv_key`
/// and returns the decrypted polynomial.
///
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

/// Encrypts a polynomial in the F3 field using a public key in the Fq field.
///
/// # Arguments
///
/// - `r`: The polynomial to be encrypted in the F3 field.
/// - `pub_key`: The public key used for encryption in the Fq field.
///
/// # Returns
///
/// Returns the ciphertext polynomial as a result of applying the public key to `r`.
///
/// # Example
///
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::ntru::cipher::rq_decrypt;
/// use ntrulp::ntru::cipher::r3_encrypt;
/// use ntrulp::key::pub_key::PubKey;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate an content for encrypt
/// let r: R3 = Rq::from(random.short_random().unwrap()).r3_from_rq();
///
/// // Generate the private key priv_key
/// let priv_key = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break s,
///         Err(_) => continue,
///     };
/// };
/// let pub_key = PubKey::from_sk(&priv_key).unwrap();
///
/// let encrypted = r3_encrypt(&r, &pub_key);
/// let decrypted = rq_decrypt(&encrypted, &priv_key);
/// ```
///
/// # Notes
///
/// This function encrypts a polynomial `r` in the F3 field using a public key `pub_key`
/// in the Fq field and returns the ciphertext polynomial.
///
pub fn r3_encrypt(r: &R3, pub_key: &PubKey) -> Rq {
    let mut hr = pub_key.mult_r3(&r);

    round(&mut hr.coeffs);

    hr
}

/// Encrypts a slice of bytes using the provided `NTRURandom` instance and the recipient's public key.
///
/// # Arguments
///
/// * `rng`: An instance of `NTRURandom` used for encryption.
/// * `bytes`: A slice of bytes to be encrypted.
/// * `pub_key`: The public key of the recipient.
///
/// # Returns
///
/// Returns the encrypted bytes.
///
/// # Example
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::ntru::cipher::bytes_encrypt;
/// use ntrulp::ntru::cipher::bytes_decrypt;
/// use ntrulp::key::pub_key::PubKey;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate the private key priv_key
/// let sk = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break s,
///         Err(_) => continue,
///     };
/// };
///
/// // Generate an content for encrypt
/// let ciphertext = random.randombytes::<123>();
///
/// let pk = PubKey::from_sk(&sk).unwrap();
/// let encrypted = bytes_encrypt(&mut random, &ciphertext, &pk);
/// let decrypted = bytes_decrypt(&encrypted, &sk).unwrap();
/// ```
///
/// # Panics
///
/// The function may panic if encryption fails or if the provided public key is invalid.
///
pub fn bytes_encrypt(rng: &mut NTRURandom, bytes: &[u8], pub_key: &PubKey) -> Vec<u8> {
    let unlimted_poly = r3::r3_decode_chunks(bytes);
    let (chunks, size, seed) = r3::r3_split_w_chunks(&unlimted_poly, rng);
    let mut bytes: Vec<u8> = Vec::with_capacity(P * size.len());

    for chunk in chunks {
        let r3 = R3::from(chunk);
        let hr = r3_encrypt(&r3, pub_key);
        let rq_bytes = rq::encode(&hr.coeffs);

        bytes.extend(rq_bytes);
    }

    pack_bytes(bytes, size, seed)
}

/// Decrypts bytes and retrieves the bytes previously encrypted using the `bytes_encrypt` function.
///
/// # Arguments
///
/// * `bytes`: A slice of bytes to decrypt.
/// * `priv_key`: The private key used for decryption.
///
/// # Returns
///
/// Returns the decrypted bytes.
///
/// # Example
///
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::ntru::cipher::bytes_encrypt;
/// use ntrulp::ntru::cipher::bytes_decrypt;
/// use ntrulp::key::pub_key::PubKey;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate the private key priv_key
/// let sk = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break s,
///         Err(_) => continue,
///     };
/// };
///
/// // Generate an content for encrypt
/// let ciphertext = random.randombytes::<123>();
///
/// let pk = PubKey::from_sk(&sk).unwrap();
/// let encrypted = bytes_encrypt(&mut random, &ciphertext, &pk);
/// let decrypted = bytes_decrypt(&encrypted, &sk).unwrap();
/// ```
///
/// # Panics
///
/// The function may panic if decryption fails or if the private key is invalid.
///
pub fn bytes_decrypt<'a>(bytes: &[u8], priv_key: &PrivKey) -> Result<Vec<u8>, NTRUErrors<'a>> {
    let (bytes_data, size, seed) = unpack_bytes(&bytes)?;
    let chunks = bytes_data.chunks(RQ_BYTES);
    let size_len = size.len();

    let mut r3_chunks = Vec::with_capacity(size_len);

    for chunk in chunks {
        let rq_chunk: [u8; RQ_BYTES] = match chunk.try_into() {
            Ok(c) => c,
            Err(_) => {
                return Err(NTRUErrors::SliceError(
                    "Cannot into [u8; RQ_BYTES], Incorrect cipher!",
                ))
            }
        };
        let rq = Rq::from(rq::decode(&rq_chunk));
        let r3 = rq_decrypt(&rq, priv_key);

        r3_chunks.push(r3.coeffs);
    }

    let out_r3 = r3::r3_merge_w_chunks(&r3_chunks, &size, seed);

    Ok(r3::r3_encode_chunks(&out_r3))
}

/// Encrypts bytes in parallel using multiple processor threads and the provided `NTRURandom` instance and recipient's public key.
///
/// # Arguments
///
/// * `rng`: An instance of `NTRURandom` used for encryption.
/// * `bytes`: Bytes to be encrypted.
/// * `pub_key`: The public key of the recipient.
/// * `num_threads`: The number of processor threads to use for parallel encryption.
///
/// # Returns
///
/// Returns the encrypted bytes.
///
/// # Example
///
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::key::pub_key::PubKey;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// use ntrulp::ntru::cipher::parallel_bytes_encrypt;
/// use ntrulp::ntru::cipher::parallel_bytes_decrypt;
/// use std::sync::Arc;
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate the private key priv_key
/// let sk = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break Arc::new(s),
///         Err(_) => continue,
///     };
/// };
///
/// // Generate an content for encrypt
/// let ciphertext = Arc::new(random.randombytes::<128>().to_vec());
///
/// // set nums threads
/// let num_threads = 2;
/// let pk = Arc::new(PubKey::compute(&f, &g).unwrap());
/// let encrypted =
///    Arc::new(parallel_bytes_encrypt(&mut random, &ciphertext, &pk, num_threads).unwrap());
/// let decrypted = parallel_bytes_decrypt(&encrypted, &sk, num_threads).unwrap();

/// assert_eq!(decrypted, ciphertext.to_vec());
/// ```
///
/// # Panics
///
/// The function may panic if encryption fails, the provided public key is invalid,
/// or if the specified number of threads exceeds the available processor cores.
///
pub fn parallel_bytes_encrypt<'a>(
    rng: &mut NTRURandom,
    bytes: &Arc<Vec<u8>>,
    pub_key: &Arc<PubKey>,
    num_threads: usize,
) -> Result<Vec<u8>, NTRUErrors<'a>> {
    let unlimted_poly = r3::r3_decode_chunks(&bytes);
    let (chunks, size, seed) = r3::r3_split_w_chunks(&unlimted_poly, rng);

    let mut bytes: Vec<u8> = Vec::with_capacity(P * size.len());
    let mut threads = Vec::with_capacity(num_threads);
    let enc: Arc<Mutex<HashMap<usize, [u8; RQ_BYTES]>>> = Arc::new(Mutex::new(HashMap::new()));

    for (index, chunk) in chunks.into_iter().enumerate() {
        let pub_key_ref = Arc::clone(&pub_key);
        let enc_ref = Arc::clone(&enc);
        let handle = thread::spawn(move || {
            let r3 = R3::from(chunk);
            let h = pub_key_ref;
            let hr = r3_encrypt(&r3, &h);
            let rq_bytes = rq::encode(&hr.coeffs);
            let mut enc = match enc_ref.lock() {
                Ok(v) => v,
                Err(_) => return Err(NTRUErrors::ThreadError("cannot lock enc arc value")),
            };

            enc.insert(index, rq_bytes);

            Ok(())
        });

        threads.push(handle);

        // wait for last first to last
        if threads.len() >= num_threads {
            let handle = threads.remove(0);

            match handle.join() {
                Ok(_) => continue,
                Err(_) => {
                    return Err(NTRUErrors::ThreadError(
                        "Cannot done the thread, check your init params!",
                    ))
                }
            };
        }
    }

    // Wait for done all tasks
    for h in threads {
        match h.join() {
            Ok(_) => continue,
            Err(_) => {
                return Err(NTRUErrors::ThreadError(
                    "Cannot done the thread, check your init params!",
                ))
            }
        };
    }

    let enc_ref = match enc.lock() {
        Ok(v) => v,
        Err(_) => return Err(NTRUErrors::ThreadError("cannot lock enc arc value!")),
    };

    for i in 0..size.len() {
        match enc_ref.get(&i) {
            Some(v) => bytes.extend(v),
            None => {
                return Err(NTRUErrors::ThreadError(
                    "Mutex error check your init params!",
                ))
            }
        }
    }

    Ok(pack_bytes(bytes, size, seed))
}

/// Decrypts previously encrypted bytes in parallel using multiple processor threads.
///
/// # Arguments
///
/// * `bytes`: A reference to an `Arc<Vec<u8>>` containing the bytes to be decrypted.
/// * `priv_key`: A reference to an `Arc<PrivKey>` representing the private key for decryption.
/// * `num_threads`: The number of processor threads to use for parallel decryption.
///
/// # Returns
///
/// Returns the decrypted bytes.
///
/// # Example
///
/// ```rust
/// use ntrulp::key::priv_key::PrivKey;
/// use ntrulp::poly::rq::Rq;
/// use ntrulp::poly::r3::R3;
/// use ntrulp::key::pub_key::PubKey;
/// use ntrulp::random::{CommonRandom, NTRURandom};
///
/// use ntrulp::ntru::cipher::parallel_bytes_encrypt;
/// use ntrulp::ntru::cipher::parallel_bytes_decrypt;
/// use std::sync::Arc;
///
/// let mut random: NTRURandom = NTRURandom::new();
/// let f = Rq::from(random.short_random().unwrap());
/// let mut g: R3;
///
/// // Generate the private key priv_key
/// let sk = loop {
///     g = R3::from(random.random_small().unwrap());
///     match PrivKey::compute(&f, &g) {
///         Ok(s) => break Arc::new(s),
///         Err(_) => continue,
///     };
/// };
///
/// // Generate an content for encrypt
/// let ciphertext = Arc::new(random.randombytes::<128>().to_vec());
///
/// // set nums threads
/// let num_threads = 2;
/// let pk = Arc::new(PubKey::compute(&f, &g).unwrap());
/// let encrypted =
///    Arc::new(parallel_bytes_encrypt(&mut random, &ciphertext, &pk, num_threads).unwrap());
/// let decrypted = parallel_bytes_decrypt(&encrypted, &sk, num_threads).unwrap();

/// assert_eq!(decrypted, ciphertext.to_vec());
/// ```
///
/// # Panics
///
/// The function may panic if decryption fails or if the specified number of threads exceeds the available processor cores.
///
pub fn parallel_bytes_decrypt<'a>(
    bytes: &Arc<Vec<u8>>,
    priv_key: &Arc<PrivKey>,
    num_threads: usize,
) -> Result<Vec<u8>, NTRUErrors<'a>> {
    let (bytes_data, size, seed) = unpack_bytes(&bytes)?;
    let chunks = bytes_data.chunks(RQ_BYTES);
    let size_len = size.len();
    let sync_hash_map: Arc<Mutex<HashMap<usize, [i8; P]>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut threads = Vec::with_capacity(num_threads);

    for (index, chunk) in chunks.into_iter().enumerate() {
        let sync_map_ref = Arc::clone(&sync_hash_map);
        let priv_key_ref = Arc::clone(&priv_key);
        let rq_chunk: [u8; RQ_BYTES] = match chunk.try_into() {
            Ok(c) => c,
            Err(_) => {
                return Err(NTRUErrors::SliceError(
                    "Cannot into [u8; ROUNDED_BYTES], Incorrect params!",
                ))
            }
        };
        let handle = thread::spawn(move || {
            let sk = priv_key_ref;
            let rq = Rq::from(rq::decode(&rq_chunk));
            let r3 = rq_decrypt(&rq, &sk);
            let mut sync_map = match sync_map_ref.lock() {
                Ok(v) => v,
                Err(_) => return Err(NTRUErrors::ThreadError("cannot lock enc arc value")),
            };
            sync_map.insert(index, r3.coeffs);

            Ok(())
        });

        threads.push(handle);

        // Wait for done frist task to last
        if threads.len() >= num_threads {
            let handle = threads.remove(0);

            match handle.join() {
                Ok(_) => continue,
                Err(_) => {
                    return Err(NTRUErrors::ThreadError(
                        "Cannot done the thread, check your init params!",
                    ))
                }
            };
        }
    }

    // Wait for done all tasks
    for h in threads {
        match h.join() {
            Ok(_) => continue,
            Err(_) => {
                return Err(NTRUErrors::ThreadError(
                    "Cannot done the thread, check your init params!",
                ))
            }
        };
    }

    let out = {
        let sync_map = match sync_hash_map.lock() {
            Ok(v) => v,
            Err(_) => return Err(NTRUErrors::ThreadError("cannot lock enc arc value!")),
        };
        let mut r3_chunks = Vec::with_capacity(size_len);

        for i in 0..size.len() {
            match sync_map.get(&i) {
                Some(v) => r3_chunks.push(*v),
                None => {
                    return Err(NTRUErrors::ThreadError(
                        "Mutex error check your init params!",
                    ))
                }
            }
        }

        let r3 = r3::r3_merge_w_chunks(&r3_chunks, &size, seed);

        r3::r3_encode_chunks(&r3)
    };

    Ok(out)
}

#[cfg(test)]
mod test_cipher {
    use super::*;
    use crate::random::CommonRandom;
    use crate::random::NTRURandom;
    use rand::Rng;

    #[test]
    fn test_parallel_bytes_cipher() {
        let num_threads = 2;
        let mut random: NTRURandom = NTRURandom::new();

        let mut g: R3;
        let ciphertext = Arc::new(random.randombytes::<1024>().to_vec());
        let f: Rq = Rq::from(random.short_random().unwrap());
        let sk = loop {
            g = R3::from(random.random_small().unwrap());

            match PrivKey::compute(&f, &g) {
                Ok(s) => break Arc::new(s),
                Err(_) => continue,
            };
        };
        let pk = Arc::new(PubKey::compute(&f, &g).unwrap());
        let encrypted =
            Arc::new(parallel_bytes_encrypt(&mut random, &ciphertext, &pk, num_threads).unwrap());
        let encrypted1 =
            Arc::new(parallel_bytes_encrypt(&mut random, &ciphertext, &pk, num_threads).unwrap());

        assert_ne!(encrypted, encrypted1);

        let decrypted = parallel_bytes_decrypt(&encrypted, &sk, num_threads).unwrap();

        assert_eq!(decrypted, ciphertext.to_vec());
    }

    #[test]
    fn test_bytes_cipher() {
        let mut random: NTRURandom = NTRURandom::new();

        let mut g: R3;
        let ciphertext = random.randombytes::<1024>();
        let f: Rq = Rq::from(random.short_random().unwrap());
        let sk = loop {
            g = R3::from(random.random_small().unwrap());

            match PrivKey::compute(&f, &g) {
                Ok(s) => break s,
                Err(_) => continue,
            };
        };
        let pk = PubKey::compute(&f, &g).unwrap();
        let mut encrypted = bytes_encrypt(&mut random, &ciphertext, &pk);
        let encrypted1 = bytes_encrypt(&mut random, &ciphertext, &pk);
        assert_ne!(encrypted, encrypted1);
        let decrypted = bytes_decrypt(&encrypted, &sk).unwrap();

        assert_eq!(decrypted, ciphertext);

        encrypted[2] = 0;
        encrypted[1] = 0;
        encrypted[3] = 0;
        encrypted[4] = 0;
        encrypted[5] = 0;
        encrypted[6] = 0;

        let decrypted = bytes_decrypt(&encrypted, &sk).unwrap();

        assert_ne!(decrypted, ciphertext);
    }

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

    #[test]
    fn test_uszie_convert() {
        let mut rng = rand::thread_rng();
        let usize_list: Vec<usize> = (0..1024).map(|_| rng.gen::<usize>()).collect();
        let bytes = usize_vec_to_bytes(&usize_list);
        let out = byte_to_usize_vec(&bytes);

        assert_eq!(out, usize_list);
    }
}
