extern crate num_bigint;
use num_bigint::BigUint;
use std::convert::TryInto;

/// Clamps a scalar per RFC 7748 for use with X25519.
pub fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Converts a 32-byte little-endian array into a BigUint.
pub fn bytes_to_biguint_le(bytes: &[u8; 32]) -> BigUint {
    let mut be = bytes.clone();
    be.reverse(); // convert to big-endian order
    BigUint::from_bytes_be(&be)
}

/// Converts a BigUint into a 32-byte little-endian array (padding if needed).
pub fn biguint_to_bytes_le(n: &BigUint) -> [u8; 32] {
    let mut be = n.to_bytes_be();
    if be.len() < 32 {
        let mut padded = vec![0u8; 32 - be.len()];
        padded.extend_from_slice(&be);
        be = padded;
    }
    be.reverse(); // convert back to little-endian order
    be.try_into().expect("Slice with incorrect length")
}
