extern crate curve25519_dalek;
extern crate sodiumoxide;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sodiumoxide::randombytes;

// ─────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────

/// Generates a random Ristretto255 key pair.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&randombytes::randombytes(64));
    let priv_scalar = Scalar::from_bytes_mod_order_wide(&wide);
    let pub_point: RistrettoPoint = &priv_scalar * &RISTRETTO_BASEPOINT_POINT;
    (priv_scalar.to_bytes(), pub_point.compress().to_bytes())
}

/// Adds two compressed Ristretto public keys and returns the compressed sum.
pub fn add_public_points(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let pa = CompressedRistretto(*a)
        .decompress()
        .expect("invalid point a");
    let pb = CompressedRistretto(*b)
        .decompress()
        .expect("invalid point b");
    (pa + pb).compress().to_bytes()
}

/// Combine two private scalars (little‑endian) modulo ℓ.
pub fn combine_scalars(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let sa = Scalar::from_bytes_mod_order(*a);
    let sb = Scalar::from_bytes_mod_order(*b);
    (sa + sb).to_bytes()
}

/// Derive the public key corresponding to a private scalar.
pub fn derive_public_key(priv_key: &[u8; 32]) -> [u8; 32] {
    let s = Scalar::from_bytes_mod_order(*priv_key);
    (&s * &RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
}

// ─────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_combine() {
        let (static_priv, static_pub) = generate_keypair();
        let (e_priv, e_pub) = generate_keypair();

        let combined_priv = combine_scalars(&static_priv, &e_priv);
        let combined_pub = derive_public_key(&combined_priv);

        let combined_pub_pa = add_public_points(&static_pub, &e_pub);

        assert_eq!(combined_pub, combined_pub_pa);
        assert_ne!(combined_pub, static_pub);
        assert_ne!(combined_pub, e_pub);
    }

    #[test]
    fn test_multi_party_interaction() {
        let (user_static_priv, user_static_pub) = generate_keypair();
        let (srv_ephemeral_priv, srv_ephemeral_pub) = generate_keypair();

        let user_session_pub = add_public_points(&user_static_pub, &srv_ephemeral_pub);

        // Service verification with public data
        let expected_pub = add_public_points(&user_static_pub, &srv_ephemeral_pub);
        assert_eq!(user_session_pub, expected_pub);

        // Cross‑check via scalar path (server wouldn’t do this in prod)
        let session_priv_scalar = combine_scalars(&user_static_priv, &srv_ephemeral_priv);
        let session_pub_scalar = derive_public_key(&session_priv_scalar);
        assert_eq!(session_pub_scalar, user_session_pub);
    }
}
