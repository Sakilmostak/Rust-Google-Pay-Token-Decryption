// use aes_gcm::aead::Aead; // AES-GCM traits for Aead encryption
// use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce}; // AES-GCM for encryption/decryption
use anyhow::{anyhow, Result};
use base64::Engine;
use core::str;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::{
    derive::Deriver,
    symm::{decrypt_aead, Cipher},
};
use ring::hmac;
use rust_hkdf::Hkdf;
use serde_json::{self, Value};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use std::error::Error;

pub const SENDER_ID: &[u8] = b"Google";
pub const BASE64_ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

// Error handling with custom error types
#[derive(Debug)]
pub struct GooglePayError(String);

impl Error for GooglePayError {}

impl std::fmt::Display for GooglePayError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Google Pay Error: {}", self.0)
    }
}

// Structs for keys and the main decryptor
pub struct GooglePayTokenDecryptor {
    #[allow(dead_code)]
    root_signing_keys: Vec<Value>,
    #[allow(dead_code)]
    recipient_id: String,
    private_key: PKey<Private>,
}

// Helper function for constructing signed data
// fn construct_signed_data(args: Vec<&str>) -> Vec<u8> {
//     let mut signed = vec![];
//     for a in args {
//         signed.extend((a.len() as u32).to_le_bytes().iter()); // 4-byte little-endian length
//         signed.extend(a.as_bytes()); // UTF-8 encoded
//     }
//     signed
// }

// Check expiration date validity
fn check_expiration_date_is_valid(expiration: &str) -> bool {
    let expiration_ms: u64 = expiration.parse().unwrap_or(0);
    let current_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;
    current_ms < expiration_ms
}

// Decryption method for GooglePayTokenDecryptor (highly simplified)
impl GooglePayTokenDecryptor {
    pub fn new(
        root_keys: Vec<Value>,
        recipient_id: String,
        private_key: &[u8],
    ) -> Result<Self, GooglePayError> {
        // let rng = SystemRandom::new();
        // let private_key = EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        //     .map_err(|_| GooglePayError("Invalid private key".to_string()))?;
        let decoded_key = BASE64_ENGINE
            .decode(
                str::from_utf8(private_key)
                    .map_err(|_| GooglePayError("Failed to decode the private key".to_string()))?,
            )
            .map_err(|_| GooglePayError("Failed to decode the private key".to_string()))?;
        let private_key = PKey::private_key_from_pkcs8(&decoded_key)
            .map_err(|_| GooglePayError("Invalid private key".to_string()))?;

        Ok(Self {
            root_signing_keys: root_keys,
            recipient_id,
            private_key,
        })
    }

    pub fn decrypt_token(&self, data: &str, verify: bool) -> Result<Value, GooglePayError> {
        let encrypted_data: Value = serde_json::from_str(data)
            .map_err(|_| GooglePayError("Invalid JSON data".to_string()))?;

        // Verify the signature if required
        if verify {
            // self.verify_signature(&encrypted_data)?;
        }

        // Load the signed message from the token
        let signed_message: Value = serde_json::from_str(
            encrypted_data
                .get("signedMessage")
                .ok_or_else(|| GooglePayError("signedMessage missing".to_string()))?
                .as_str()
                .unwrap(),
        )
        .map_err(|_| GooglePayError("signedMessage missing".to_string()))?;

        // Base64 decode the required fields
        let ephemeral_public_key = BASE64_ENGINE
            .decode(
                signed_message["ephemeralPublicKey"]
                    .as_str()
                    .ok_or_else(|| GooglePayError("ephemeralPublicKey missing".to_string()))?,
            )
            .map_err(|_| GooglePayError("ephemeralPublicKey missing".to_string()))?;
        let tag = BASE64_ENGINE
            .decode(
                signed_message["tag"]
                    .as_str()
                    .ok_or_else(|| GooglePayError("tag missing".to_string()))?,
            )
            .map_err(|_| GooglePayError("tag missing".to_string()))?;
        let encrypted_message = BASE64_ENGINE
            .decode(
                signed_message["encryptedMessage"]
                    .as_str()
                    .ok_or_else(|| GooglePayError("encryptedMessage missing".to_string()))?,
            )
            .map_err(|_| GooglePayError("encryptedMessage missing".to_string()))?;

        // Derive the shared key
        let shared_key = self
            .get_shared_key(&ephemeral_public_key)
            .map_err(|_| GooglePayError("sharedKey missing".to_string()))?;

        // Derive the symmetric encryption key and MAC key
        let derived_key = self
            .derive_key(&ephemeral_public_key, &shared_key)
            .map_err(|_| GooglePayError("derivedKey missing".to_string()))?;
        let symmetric_encryption_key = &derived_key[..32]; // First 32 bytes for AES-256
        let mac_key = &derived_key[32..]; // Remaining bytes for HMAC

        // Verify the HMAC of the message
        self.verify_hmac(mac_key, &tag, &encrypted_message)
            .map_err(|_| GooglePayError("Hmac verification failed".to_string()))?;

        // Decrypt the message
        let decrypted = self
            .decrypt_message(symmetric_encryption_key, &encrypted_message)
            .map_err(|_| GooglePayError("Cannot decrypt the message".to_string()))?;

        // Parse the decrypted data
        let decrypted_data: Value = serde_json::from_slice(&decrypted)
            .map_err(|_| GooglePayError("Failed to get the decrypted data".to_string()))?;

        // Check the expiration date of the decrypted data
        if !check_expiration_date_is_valid(
            decrypted_data["messageExpiration"].as_str().unwrap_or(""),
        ) {
            return Err(GooglePayError("The token has expired".to_string()));
        }

        Ok(decrypted_data)
    }

    // Derive a shared key using ECDH
    fn get_shared_key(&self, ephemeral_public_key_bytes: &[u8]) -> Result<Vec<u8>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

        let mut big_num_context = BigNumContext::new()?;

        let ec_key = EcPoint::from_bytes(&group, ephemeral_public_key_bytes, &mut big_num_context)?;

        // Create an ephemeral public key from the given bytes
        let ephemeral_public_key = EcKey::from_public_key(&group, &ec_key)?;

        // Wrap the public key in a PKey
        let ephemeral_pkey = PKey::from_ec_key(ephemeral_public_key)?;

        // Perform ECDH to derive the shared key
        let mut deriver = Deriver::new(&self.private_key)?;
        deriver.set_peer(&ephemeral_pkey)?;
        let shared_key = deriver.derive_to_vec()?;

        Ok(shared_key)
    }

    // Derive symmetric key and MAC key using HKDF
    fn derive_key(&self, ephemeral_public_key_bytes: &[u8], shared_key: &[u8]) -> Result<Vec<u8>> {
        // Concatenate ephemeral public key and shared key
        let input_key_material = [ephemeral_public_key_bytes, shared_key].concat();

        // Initialize HKDF with SHA-256 as the hash function
        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0u8; 32]), &input_key_material); // 32 zeroed bytes as salt

        // Derive 64 bytes for the output key (symmetric encryption + MAC key)
        let mut okm = vec![0u8; 64];
        hkdf.expand(SENDER_ID, &mut okm)
            .expect("HKDF expand should succeed");

        Ok(okm)
    }

    fn verify_hmac(&self, mac_key: &[u8], tag: &[u8], encrypted_message: &[u8]) -> Result<()> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        hmac::verify(&hmac_key, encrypted_message, tag).map_err(|_| anyhow!("Invalid HMAC"))?;
        Ok(())
    }

    // Method to decrypt the AES-GCM encrypted message
    fn decrypt_message(&self, symmetric_key: &[u8], encrypted_message: &[u8]) -> Result<Vec<u8>> {
        let iv = [0u8; 16]; //Initialization vector IV is typically used in AES-GCM (Galois/Counter Mode) encryption for randomizing the encryption process.
        let ciphertext = encrypted_message;
        let tag = encrypted_message
            .get(encrypted_message.len() - 16..)
            .ok_or_else(|| anyhow!("failed to create ciphertext"))?;
        let cipher = Cipher::aes_256_ctr();
        let decrypted_data = decrypt_aead(cipher, symmetric_key, Some(&iv), &[], ciphertext, tag)?;
        // let decrypted = String::from_utf8(decrypted_data)?;

        Ok(decrypted_data)
    }
}
