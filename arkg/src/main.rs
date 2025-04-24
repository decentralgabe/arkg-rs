mod crypto;

fn main() {
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");

    let (static_priv, static_pub) = crypto::generate_keypair();
    let (ephemeral_priv, ephemeral_pub) = crypto::generate_keypair();

    // Combine the private keys.
    let combined_priv = crypto::combine_scalars(&static_priv, &ephemeral_priv);
    let combined_pub = crypto::derive_public_key(&combined_priv);

    println!("Static Private Key:    {}", hex::encode(static_priv));
    println!("Static Public Key:     {}", hex::encode(static_pub));
    println!("Ephemeral Private Key: {}", hex::encode(ephemeral_priv));
    println!("Ephemeral Public Key:  {}", hex::encode(ephemeral_pub));
    println!("Combined Private Key:  {}", hex::encode(combined_priv));
    println!("Combined Public Key:   {}", hex::encode(combined_pub));
}
