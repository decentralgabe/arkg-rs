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
    let big_a = bytes_to_biguint_le(a);
    let big_b = bytes_to_biguint_le(b);

    // Compute the subgroup order for Curve25519:
    // order = 2^252 + 27742317777372353535851937790883648493
    let two_pow_252 = BigUint::one() << 252;
    let constant = BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10)
        .expect("Invalid constant");
    let order = two_pow_252 + constant;

    let combined = (big_a + big_b) % order;
    biguint_to_bytes_le(&combined)
}

/// Derives a public key from a given 32-byte private key.
pub fn derive_public_key(priv_key: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_slice(priv_key).expect("Scalar::from_slice requires a 32-byte slice");
    let group_elem: GroupElement = scalarmult_base(&scalar);
    group_elem.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_new_public_keys() {
        // Generate a static (long-term) keypair.
        let (static_priv, static_pub) = generate_keypair();
        assert_eq!(static_priv.len(), 32);
        assert_eq!(static_pub.len(), 32);

        // Generate an ephemeral keypair.
        let (ephemeral_priv, ephemeral_pub) = generate_keypair();
        assert_eq!(ephemeral_priv.len(), 32);
        assert_eq!(ephemeral_pub.len(), 32);

        // Combine the private keys and derive the combined public key.
        let combined_priv = combine_scalars(&static_priv, &ephemeral_priv);
        let combined_pub = derive_public_key(&combined_priv);

        // Validate that the combined public key has 32 bytes.
        assert_eq!(combined_pub.len(), 32);

        // Check that the combined public key is different from the static and ephemeral ones.
        assert_ne!(
            combined_pub, static_pub,
            "Combined public key should differ from the static public key"
        );
        assert_ne!(
            combined_pub, ephemeral_pub,
            "Combined public key should differ from the ephemeral public key"
        );

        // Now simulate generating several new public keys on the fly using the same static private key.
        let mut new_public_keys = Vec::new();
        for _ in 0..10 {
            let (new_ephemeral_priv, _new_ephemeral_pub) = generate_keypair();
            let new_combined_priv = combine_scalars(&static_priv, &new_ephemeral_priv);
            let new_combined_pub = derive_public_key(&new_combined_priv);
            new_public_keys.push(new_combined_pub);
        }
        // Ensure that all newly generated public keys are unique.
        for i in 0..new_public_keys.len() {
            for j in (i + 1)..new_public_keys.len() {
                assert_ne!(
                    new_public_keys[i], new_public_keys[j],
                    "Duplicate public keys found in on-the-fly generation"
                );
            }
        }
    }

    #[test]
    fn test_multi_party_interaction() {
        // Simulate an individual with a long-lived (static) keypair.
        let (static_priv, static_pub) = generate_keypair();

        // Both Service A and Service B have the individual's static public key.
        // Now the individual visits Service A:
        let (service_a_ephemeral_priv, _service_a_ephemeral_pub) = generate_keypair();
        let service_a_combined_priv = combine_scalars(&static_priv, &service_a_ephemeral_priv);
        let service_a_derived_pub = derive_public_key(&service_a_combined_priv);

        // And then visits Service B:
        let (service_b_ephemeral_priv, _service_b_ephemeral_pub) = generate_keypair();
        let service_b_combined_priv = combine_scalars(&static_priv, &service_b_ephemeral_priv);
        let service_b_derived_pub = derive_public_key(&service_b_combined_priv);

        // Each service sees a derived public key that is different from the stored static public key:
        assert_ne!(
            service_a_derived_pub, static_pub,
            "Service A's derived public key should differ from the registered static public key"
        );
        assert_ne!(
            service_b_derived_pub, static_pub,
            "Service B's derived public key should differ from the registered static public key"
        );

        // And importantly, the derived public keys for Service A and B are distinct:
        assert_ne!(
            service_a_derived_pub, service_b_derived_pub,
            "The derived public keys for Service A and Service B should be unique"
        );

        // This simulates how an individual can use one long-lived keypair
        // to generate distinct session-specific keys for different services.
    }
}
