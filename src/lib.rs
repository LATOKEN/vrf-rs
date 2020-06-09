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
use failure::_core::ptr::null;
use std::str;
use std::ffi::{
    CStr,
    CString
};
use libc::c_char;

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
pub extern fn evaluate(private: *const c_char, msg: *const c_char) -> CString {

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    // Inputs: Secret Key, Public Key (derived) & Message
    let prv = unsafe { CStr::from_ptr(private) }.to_str().unwrap();
    let secret_key =
        hex::decode(prv).unwrap();

    let message = unsafe { CStr::from_ptr(msg) }.to_str().unwrap().as_bytes();

    let proof = vrf.prove(&secret_key, &message).unwrap();

    return CString::new(hex::encode(&proof).to_string()).unwrap();
}

#[no_mangle]
pub extern fn verify(public: *const c_char, prf: *const c_char, msg: *const c_char) -> bool {

    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let pub_key = unsafe { CStr::from_ptr(public) }.to_str().unwrap();
    let public_key =
        hex::decode(pub_key).unwrap();

    let message = unsafe { CStr::from_ptr(msg) }.to_str().unwrap().as_bytes();

    let proof = hex::decode(unsafe { CStr::from_ptr(prf) }.to_str().unwrap()).unwrap();

    let val = vrf.proof_to_hash(&proof).unwrap();

    // VRF proof verification (returns VRF hash output)
    let beta = vrf.verify(&public_key, &proof, &message);

    // proof
    match beta {
        Ok(beta) => {
            val == beta
        }
        Err(e) => {
            false
        }
    }
}

#[no_mangle]
pub extern fn proof_to_hash(proof_hex: *const c_char) -> CString {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let proof = hex::decode(unsafe { CStr::from_ptr(proof_hex) }.to_str().unwrap()).unwrap();
    let val = vrf.proof_to_hash(&proof).unwrap();
    return CString::new(hex::encode(&val)).unwrap()
}
