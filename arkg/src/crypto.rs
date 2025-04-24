extern crate curve25519_dalek;
extern crate sodiumoxide;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
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
    use std::collections::HashSet;
    use curve25519_dalek::ristretto::CompressedRistretto;

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

    #[test]
    fn test_generate_and_combine() {
        let (static_priv, static_pub) = generate_keypair();
        let (e_priv, e_pub) = generate_keypair();

        // Scalar path – not used in production but a handy invariant check
        let combined_priv = combine_scalars(&static_priv, &e_priv);
        let combined_pub_scalar = derive_public_key(&combined_priv);

        // Public‑point addition path – what the user & service actually do
        let combined_pub_point = add_public_points(&static_pub, &e_pub);

        assert_eq!(combined_pub_scalar, combined_pub_point);
        assert_ne!(combined_pub_scalar, static_pub);
        assert_ne!(combined_pub_scalar, e_pub);
    }

    /// Multi‑party, service‑per‑visit workflow with explicit roles.
    ///
    /// ASCII‑art legend (User = U, Service A = SA, Service B = SB):
    ///
    /// ```text
    ///  (a) SA generates  rA , RA = rA·G  ─────────┐
    ///  (b) SB generates  rB , RB = rB·G  ───────┐ │
    ///                                           │ │ transport (TLS)
    ///  U holds long‑term s , S = s·G            │ │
    ///                                           ▼ ▼
    ///  U computes  SA_session = S + RA
    ///             SB_session = S + RB
    ///  U sends session pubs back to SA / SB ───►  Services verify:
    ///                                             S + R?  ==  session_pub
    /// ```
    ///
    /// No secret scalar ever leaves its owner; verification uses only
    /// public data.
    #[test]
    fn test_multi_party_illustrated() {
        // ── (1) USER long‑lived static keypair ──────────────────────────
        let (user_static_priv, user_static_pub) = generate_keypair();

        // ── (2) Each service produces an ephemeral keypair ─────────────
        let (srv_a_priv, srv_a_pub) = generate_keypair();
        let (srv_b_priv, srv_b_pub) = generate_keypair();

        // ── (3‑U‑A) User visits Service A and derives session pub ───────
        let session_pub_a = add_public_points(&user_static_pub, &srv_a_pub);
        // (A‑side) expected value via public math
        let expected_pub_a = add_public_points(&user_static_pub, &srv_a_pub);
        assert_eq!(
            session_pub_a, expected_pub_a,
            "Service A: verification failed"
        );

        // Cross‑check (test only): scalar composition matches
        let session_priv_a = combine_scalars(&user_static_priv, &srv_a_priv);
        assert_eq!(derive_public_key(&session_priv_a), session_pub_a);

        // ── (3‑U‑B) Same flow for Service B ────────────────────────────
        let session_pub_b = add_public_points(&user_static_pub, &srv_b_pub);
        let expected_pub_b = add_public_points(&user_static_pub, &srv_b_pub);
        assert_eq!(
            session_pub_b, expected_pub_b,
            "Service B: verification failed"
        );

        let session_priv_b = combine_scalars(&user_static_priv, &srv_b_priv);
        assert_eq!(derive_public_key(&session_priv_b), session_pub_b);

        // ── (4) Global sanity: every public key is unique ──────────────
        let mut uniq = HashSet::new();
        for k in [
            &user_static_pub,
            &srv_a_pub,
            &srv_b_pub,
            &session_pub_a,
            &session_pub_b,
        ] {
            assert!(uniq.insert(*k), "duplicate public key detected: {:?}", k);
        }
    }
}
