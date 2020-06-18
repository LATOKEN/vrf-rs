//! # Verifiable Random Function (VRF)
//!
//! This crate defines the generic contract that must be followed by VRF implementations ([`VRF`](trait.VRF.html) trait).
//!
//! ## Elliptic Curve VRF
//!
//! The [`openssl`](openssl/index.html) module provides an implementation of Elliptic Curve VRF ([`ECVRF`](openssl/struct.ECVRF.html)).
//!
//! It follows the algorithms described in:
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//!
//! Currently the supported cipher suites are:
//!
//! * `P256_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST P-256` curve.
//! * `K163_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `NIST K-163` curve.
//! * `SECP256K1_SHA256_TAI`: the aforementioned algorithms with `SHA256` and the `secp256k1` curve.
extern crate libc;

use crate::openssl::{ECVRF, CipherSuite};
use c_vec::CVec;
use std::os::raw::c_int;

pub mod dummy;
pub mod openssl;

/// A trait containing the common capabilities for all Verifiable Random Functions (VRF) implementations.
pub trait VRF<PublicKey, SecretKey> {
    type Error;

    /// Generates proof from a secret key and a message.
    ///
    /// # Arguments
    ///
    /// * `x`     - A secret key.
    /// * `alpha` - A slice representing the message in octets.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets representing the proof of the VRF.
    fn prove(&mut self, x: SecretKey, alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Verifies the provided VRF proof and computes the VRF hash output.
    ///
    /// # Arguments
    ///
    /// * `y`   - A public key.
    /// * `pi`  - A slice of octets representing the VRF proof.
    ///
    /// # Returns
    ///
    /// * If successful, a vector of octets with the VRF hash output.
    fn verify(&mut self, y: PublicKey, pi: &[u8], alpha: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[no_mangle]
pub extern fn evaluate(private: *mut u8, private_len: c_int, message: *mut u8, message_len: c_int, result: *mut u8, max_result_len: c_int) -> c_int {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    unsafe {
        let secret_key: Vec<u8> = CVec::new(private, private_len as usize).into();
        let message: Vec<u8> = CVec::new(message, message_len as usize).into();
        let proof = vrf.prove(&secret_key, &message).unwrap();
        if proof.len() > max_result_len as usize {
            return 0;
        }
        std::ptr::copy(proof.as_ptr(), result, proof.len());
        return proof.len() as c_int;
    }
}

#[no_mangle]
pub extern fn verify(public_key: *mut u8, public_key_len: c_int, proof: *mut u8, proof_len: c_int, message: *mut u8, message_len: c_int) -> bool {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    unsafe {
        let public_key: Vec<u8> = CVec::new(public_key, public_key_len as usize).into();
        let proof: Vec<u8> = CVec::new(proof, proof_len as usize).into();
        let message: Vec<u8> = CVec::new(message, message_len as usize).into();
        let val = vrf.proof_to_hash(&proof).unwrap();
        // VRF proof verification (returns VRF hash output)
        let beta = vrf.verify(&public_key, &proof, &message);
        return match beta {
            Ok(beta) => val == beta,
            Err(_) => false
        }
    }
}

#[no_mangle]
pub extern fn proof_to_hash(proof: *mut u8, proof_len: c_int, result: *mut u8, max_result_len: c_int) -> c_int {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    unsafe {
        let proof: Vec<u8> = CVec::new(proof, proof_len as usize).into();
        let val = vrf.proof_to_hash(&proof).unwrap();
        if val.len() > max_result_len as usize {
            return 0
        }
        std::ptr::copy(val.as_ptr(), result, val.len());
        return val.len() as c_int;
    }

}
