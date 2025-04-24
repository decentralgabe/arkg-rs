extern crate num_bigint;
extern crate num_traits;
extern crate sodiumoxide;

use crate::utils::{biguint_to_bytes_le, bytes_to_biguint_le, clamp_scalar};
use num_bigint::BigUint;
use num_traits::One;
use sodiumoxide::crypto::scalarmult::curve25519::{GroupElement, Scalar, scalarmult_base};
use sodiumoxide::randombytes;
use std::convert::TryInto;

/// Generates a new 32-byte private key (after clamping) along with its public key.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    // Generate a random 32-byte array.
    let mut priv_key: [u8; 32] = randombytes::randombytes(32)
        .as_slice()
        .try_into()
        .expect("Expected 32 random bytes");

    // Clamp the key per RFC 7748.
    clamp_scalar(&mut priv_key);

    // Convert our raw private key into a Scalar.
    let scalar =
        Scalar::from_slice(&priv_key).expect("Scalar::from_slice requires a 32-byte slice");
    // Derive the public key.
    let pub_key: GroupElement = scalarmult_base(&scalar);
    (priv_key, pub_key.0)
}

/// Combines two 32-byte scalars (interpreted as little-endian numbers) modulo the Curve25519 subgroup order.
pub fn combine_scalars(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a = bytes_to_biguint_le(a);
    let b = bytes_to_biguint_le(b);

    // Compute the subgroup order for Curve25519:
    // order = 2^252 + 27742317777372353535851937790883648493
    let two_pow_252 = BigUint::one() << 252;
    let constant = BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
        .expect("Invalid constant");
    let order = two_pow_252 + constant;

    let combined = (a + b) % order;
    biguint_to_bytes_le(&combined)
}

/// Derives a public key from a given 32-byte private key.
pub fn derive_public_key(priv_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_slice(priv_key).expect("Scalar::from_slice requires a 32-byte slice");
    let group_elem: GroupElement = scalarmult_base(&scalar);
    group_elem.0
}
