//! Utilities for secure random number generation.
//!
//! # Examples
//!
//! To generate a buffer with cryptographically strong bytes:
//!
//! ```
//! use openssl::rand::rand_bytes;
//!
//! let mut buf = [0; 256];
//! rand_bytes(&mut buf).unwrap();
//! ```
use libc::c_int;

use crate::cvt;
use crate::error::ErrorStack;

/// Fill buffer with cryptographically strong pseudo-random bytes.
///
/// This corresponds to [`RAND_bytes`].
///
/// # Examples
///
/// To generate a buffer with cryptographically strong bytes:
///
/// ```
/// use openssl::rand::rand_bytes;
///
/// let mut buf = [0; 256];
/// rand_bytes(&mut buf).unwrap();
/// ```
///
/// [`RAND_bytes`]: https://www.openssl.org/docs/man1.1.0/crypto/RAND_bytes.html
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ErrorStack> {
    unsafe {
        ffi::init();
        assert!(buf.len() <= c_int::max_value() as usize);
        cvt(ffi::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int)).map(|_| ())
    }
}

/// Controls random device file descriptor behavior.
///
/// Requires OpenSSL 1.1.1 or newer.
///
/// This corresponds to [`RAND_keep_random_devices_open`].
///
/// [`RAND_keep_random_devices_open`]: https://www.openssl.org/docs/manmaster/man3/RAND_keep_random_devices_open.html
#[cfg(ossl111)]
pub fn keep_random_devices_open(keep: bool) {
    unsafe {
        ffi::RAND_keep_random_devices_open(keep as c_int);
    }
}

/// Mixes the specified bytes into the PRNG state.
///
/// This corresponds to [`RAND_add`]
///
/// The data passed into this function should, in most cases, be unpredictable to an adversary.
///
/// [`RAND_add`]: https://www.openssl.org/docs/manmaster/man3/RAND_add.html
pub fn add(buf: &[u8], entropy: f64) {
    unsafe {
        ffi::RAND_add(
            buf.as_ptr() as *const libc::c_void,
            buf.len() as i32,
            entropy,
        )
    }
}

/// Mixes the specified bytes into the PRNG state.
///
/// This corresponds to [`RAND_seed`]
///
/// The data passed into this function should, in most cases, be unpredictable to an adversary.
///
/// This is equivalent to [`add`] when `entropy == buf.len()`
///
/// [`RAND_seed`]: https://www.openssl.org/docs/manmaster/man3/RAND_seed.html
pub fn seed(buf: &[u8]) {
    unsafe { ffi::RAND_seed(buf.as_ptr() as *const libc::c_void, buf.len() as i32) }
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand_bytes() {
        let mut buf = [0; 32];
        rand_bytes(&mut buf).unwrap();
    }
}
