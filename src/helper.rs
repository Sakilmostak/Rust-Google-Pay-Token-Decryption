use anyhow::{anyhow, Result};
use base64::Engine;
use core::str;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::{
    derive::Deriver,
    symm::{decrypt_aead, Cipher},
};
use ring::hmac;
use rust_hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use sha2::Sha256;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SENDER_ID: &[u8] = b"Google";
pub const PROTOCOL: &str = "ECv2";
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
    root_signing_keys: Vec<GooglePayRootSigningKey>,
    recipient_id: String,
    private_key: PKey<Private>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedData {
    signature: String,
    intermediate_signing_key: IntermediateSigningKey,
    protocol_version: GooglePayProtocolVersion,
    signed_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntermediateSigningKey {
    signed_key: String,
    signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePaySignedKey {
    key_value: String,
    key_expiration: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePayRootSigningKey {
    key_value: String,
    key_expiration: String,
    protocol_version: GooglePayProtocolVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GooglePaySignedMessage {
    encrypted_message: String,
    ephemeral_public_key: String,
    tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum GooglePayProtocolVersion {
    #[serde(rename = "ECv2")]
    EcProtocalVersion2,
}

// Check expiration date validity
fn check_expiration_date_is_valid(expiration: &str) -> bool {
    let expiration_ms: u64 = expiration.parse().unwrap_or(0);
    let current_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;
    current_ms < expiration_ms
}

// Construct little endian format of u32 in hexadecimal
fn get_little_endian_format(number: u32) -> Vec<u8> {
    number.to_le_bytes().to_vec()
}

// Filter and parse the root signing keys based on protocol version and expiration time
fn filter_root_signing_keys(root_keys: Vec<Value>) -> Vec<GooglePayRootSigningKey> {
    let root_signing_keys: Vec<GooglePayRootSigningKey> = root_keys
        .into_iter()
        .map(|key| {
            serde_json::from_value(key)
                .map_err(|err| GooglePayError(format!("{:?}", err)))
                .unwrap()
        })
        .collect();

    root_signing_keys
        .iter()
        .filter(|key| {
            key.protocol_version == GooglePayProtocolVersion::EcProtocalVersion2
                && check_expiration_date_is_valid(&key.key_expiration)
        })
        .cloned()
        .collect::<Vec<GooglePayRootSigningKey>>()
}

// Decryption method for GooglePayTokenDecryptor
impl GooglePayTokenDecryptor {
    pub fn new(
        root_keys: Vec<Value>,
        recipient_id: String,
        private_key: &[u8],
    ) -> Result<Self, GooglePayError> {
        // base64 decode the private key
        let decoded_key = BASE64_ENGINE
            .decode(
                str::from_utf8(private_key)
                    .map_err(|_| GooglePayError("Failed to decode the private key".to_string()))?,
            )
            .map_err(|_| GooglePayError("Failed to decode the private key".to_string()))?;
        // create a private key from the decoded key
        let private_key = PKey::private_key_from_pkcs8(&decoded_key)
            .map_err(|_| GooglePayError("Invalid private key".to_string()))?;

        // parse and filter the root signing keys by protocol version
        let filtered_root_signing_keys = filter_root_signing_keys(root_keys);

        Ok(Self {
            root_signing_keys: filtered_root_signing_keys,
            recipient_id,
            private_key,
        })
    }

    pub fn decrypt_token(&self, data: &str, verify: bool) -> Result<Value, GooglePayError> {
        // parse the encrypted data
        let encrypted_data: EncryptedData =
            serde_json::from_str(data).map_err(|err| GooglePayError(format!("{:?}", err)))?;

        // verify the signature if required
        if verify {
            self.verify_signature(&encrypted_data)?;
        }

        // load the signed message from the token
        let signed_message: Value = serde_json::from_str(&encrypted_data.signed_message)
            .map_err(|_| GooglePayError("Failed to load the signed message".to_string()))?;

        // base64 decode the required fields
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

        // derive the shared key
        let shared_key = self
            .get_shared_key(&ephemeral_public_key)
            .map_err(|_| GooglePayError("sharedKey missing".to_string()))?;

        // derive the symmetric encryption key and MAC key
        let derived_key = self
            .derive_key(&ephemeral_public_key, &shared_key)
            .map_err(|_| GooglePayError("derivedKey missing".to_string()))?;
        let symmetric_encryption_key = &derived_key[..32]; // First 32 bytes for AES-256
        let mac_key = &derived_key[32..]; // Remaining bytes for HMAC

        // verify the HMAC of the message
        self.verify_hmac(mac_key, &tag, &encrypted_message)
            .map_err(|_| GooglePayError("Hmac verification failed".to_string()))?;

        // decrypt the message
        let decrypted = self
            .decrypt_message(symmetric_encryption_key, &encrypted_message)
            .map_err(|_| GooglePayError("Cannot decrypt the message".to_string()))?;

        // parse the decrypted data
        let decrypted_data: Value = serde_json::from_slice(&decrypted)
            .map_err(|_| GooglePayError("Failed to get the decrypted data".to_string()))?;

        // check the expiration date of the decrypted data
        if !check_expiration_date_is_valid(
            decrypted_data["messageExpiration"].as_str().unwrap_or(""),
        ) {
            return Err(GooglePayError("The token has expired".to_string()));
        }

        Ok(decrypted_data)
    }

    // Verify the signature of the token
    fn verify_signature(&self, encrypted_data: &EncryptedData) -> Result<(), GooglePayError> {
        // check the protocol version
        if encrypted_data.protocol_version != GooglePayProtocolVersion::EcProtocalVersion2 {
            return Err(GooglePayError("Invalid protocol version".to_string()));
        }

        // verify the intermediate signing key
        self.verify_intermediate_signing_key(encrypted_data)?;
        // validate and fetch the signed key
        let signed_key = self.validate_signed_key(&encrypted_data.intermediate_signing_key)?;
        // verify the signature of the token
        self.verify_message_signature(encrypted_data, &signed_key)
    }

    // Verify the intermediate signing key
    fn verify_intermediate_signing_key(
        &self,
        encrypted_data: &EncryptedData,
    ) -> Result<(), GooglePayError> {
        let mut signatrues: Vec<EcdsaSig> = Vec::new();

        // decode and parse the signatures
        for signature in encrypted_data.intermediate_signing_key.signatures.iter() {
            let signature = BASE64_ENGINE
                .decode(signature)
                .map_err(|_| GooglePayError("signature missing".to_string()))?;
            let ecdsa_signature = EcdsaSig::from_der(&signature)
                .map_err(|_| GooglePayError("failed to parse signatrue".to_string()))?;
            signatrues.push(ecdsa_signature);
        }

        // get the sender id i.e. Google
        let sender_id = String::from_utf8(SENDER_ID.to_vec())
            .map_err(|_| GooglePayError("failed to parse sender id".to_string()))?;

        // construct the signed data
        let signed_data = self.construct_signed_data_for_intermediate_signing_key_verification(
            &sender_id,
            PROTOCOL,
            &encrypted_data.intermediate_signing_key.signed_key,
        );

        // check if any of the signatures are valid for any of the root signing keys
        for key in self.root_signing_keys.iter() {
            // decode and create public key
            let public_key = self
                .load_public_key(&key.key_value)
                .map_err(|_| GooglePayError("Failed to load the public key".to_string()))?;

            // fetch the ec key from public key
            let ec_key = public_key
                .ec_key()
                .map_err(|_| GooglePayError("failed to get ec key".to_string()))?;

            // hash the signed data
            let message_hash = sha256(&signed_data);

            // verify if any of the signatures is valid against the given key
            for signature in signatrues.iter() {
                let result = signature.verify(&message_hash, &ec_key).map_err(|_| {
                    GooglePayError("failed to verify intermediate signature".to_string())
                })?;

                if result {
                    println!("Intermediate Signature verified");
                    return Ok(());
                } else {
                    println!("Intermediate Signature NOT verified");
                }
            }
        }

        Err(GooglePayError("Invalid intermediate signature".to_string()))
    }

    // Construct signed data for intermediate signing key verification
    fn construct_signed_data_for_intermediate_signing_key_verification(
        &self,
        sender_id: &str,
        protocol_version: &str,
        signed_key: &str,
    ) -> Vec<u8> {
        let length_of_sender_id = sender_id.len() as u32;
        let length_of_protocol_version = protocol_version.len() as u32;
        let length_of_signed_key = signed_key.len() as u32;

        let mut signed_data: Vec<u8> = Vec::new();
        signed_data.append(&mut get_little_endian_format(length_of_sender_id));
        signed_data.append(&mut sender_id.as_bytes().to_vec());
        signed_data.append(&mut get_little_endian_format(length_of_protocol_version));
        signed_data.append(&mut protocol_version.as_bytes().to_vec());
        signed_data.append(&mut get_little_endian_format(length_of_signed_key));
        signed_data.append(&mut signed_key.as_bytes().to_vec());

        signed_data
    }

    // Validate and parse signed key
    fn validate_signed_key(
        &self,
        intermediate_signing_key: &IntermediateSigningKey,
    ) -> Result<GooglePaySignedKey, GooglePayError> {
        let signed_key: GooglePaySignedKey =
            serde_json::from_str(&intermediate_signing_key.signed_key)
                .map_err(|_| GooglePayError("Failed to parse the signed key".to_string()))?;
        if !check_expiration_date_is_valid(&signed_key.key_expiration) {
            return Err(GooglePayError("The signed key has expired".to_string()));
        }
        Ok(signed_key)
    }

    // Verify the signed message
    fn verify_message_signature(
        &self,
        encrypted_data: &EncryptedData,
        signed_key: &GooglePaySignedKey,
    ) -> Result<(), GooglePayError> {
        // create a public key from the intermediate signing key
        let public_key = self
            .load_public_key(&signed_key.key_value)
            .map_err(|_| GooglePayError("Failed to load the public key".to_string()))?;
        // base64 decode the signature
        let signature = BASE64_ENGINE
            .decode(&encrypted_data.signature)
            .map_err(|_| GooglePayError("signature missing".to_string()))?;

        // parse the signature using ECDSA
        let ecdsa_signature = EcdsaSig::from_der(&signature)
            .map_err(|_| GooglePayError("failed to parse signatrue".to_string()))?;

        // get the EC key from the public key
        let ec_key = public_key
            .ec_key()
            .map_err(|_| GooglePayError("failed to get ec key".to_string()))?;

        // get the sender id i.e. Google
        let sender_id = String::from_utf8(SENDER_ID.to_vec())
            .map_err(|_| GooglePayError("failed to parse sender id".to_string()))?;

        // construct the signed data
        let signed_data = self.construct_signed_data_for_signature_verification(
            &sender_id,
            PROTOCOL,
            &encrypted_data.signed_message,
        );

        // hash the signed data
        let message_hash = sha256(&signed_data);

        // verify the signature
        let result = ecdsa_signature
            .verify(&message_hash, &ec_key)
            .map_err(|_| GooglePayError("failed to verify signature".to_string()))?;

        if result {
            println!("Signature verified");
            Ok(())
        } else {
            Err(GooglePayError("Invalid signature".to_string()))
        }
    }

    // Fetch the public key
    fn load_public_key(&self, key: &str) -> Result<PKey<openssl::pkey::Public>, Box<dyn Error>> {
        // decode the base64 string
        let der_data = BASE64_ENGINE.decode(key)?;

        // parse the DER-encoded data as an EC public key
        let ec_key = EcKey::public_key_from_der(&der_data)?;

        // wrap the EC key in a PKey (a more general-purpose public key type in OpenSSL)
        let public_key = PKey::from_ec_key(ec_key)?;

        Ok(public_key)
    }

    // Construct signed data for signature verification
    fn construct_signed_data_for_signature_verification(
        &self,
        sender_id: &str,
        protocol_version: &str,
        signed_key: &str,
    ) -> Vec<u8> {
        let length_of_sender_id = sender_id.len() as u32;
        let length_of_recipient_id = self.recipient_id.len() as u32;
        let length_of_protocol_version = protocol_version.len() as u32;
        let length_of_signed_key = signed_key.len() as u32;

        let mut signed_data: Vec<u8> = Vec::new();
        signed_data.append(&mut get_little_endian_format(length_of_sender_id));
        signed_data.append(&mut sender_id.as_bytes().to_vec());
        signed_data.append(&mut get_little_endian_format(length_of_recipient_id));
        signed_data.append(&mut self.recipient_id.as_bytes().to_vec());
        signed_data.append(&mut get_little_endian_format(length_of_protocol_version));
        signed_data.append(&mut protocol_version.as_bytes().to_vec());
        signed_data.append(&mut get_little_endian_format(length_of_signed_key));
        signed_data.append(&mut signed_key.as_bytes().to_vec());

        signed_data
    }

    // Derive a shared key using ECDH
    fn get_shared_key(&self, ephemeral_public_key_bytes: &[u8]) -> Result<Vec<u8>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

        let mut big_num_context = BigNumContext::new()?;

        let ec_key = EcPoint::from_bytes(&group, ephemeral_public_key_bytes, &mut big_num_context)?;

        // create an ephemeral public key from the given bytes
        let ephemeral_public_key = EcKey::from_public_key(&group, &ec_key)?;

        // wrap the public key in a PKey
        let ephemeral_pkey = PKey::from_ec_key(ephemeral_public_key)?;

        // perform ECDH to derive the shared key
        let mut deriver = Deriver::new(&self.private_key)?;
        deriver.set_peer(&ephemeral_pkey)?;
        let shared_key = deriver.derive_to_vec()?;

        Ok(shared_key)
    }

    // Derive symmetric key and MAC key using HKDF
    fn derive_key(&self, ephemeral_public_key_bytes: &[u8], shared_key: &[u8]) -> Result<Vec<u8>> {
        // concatenate ephemeral public key and shared key
        let input_key_material = [ephemeral_public_key_bytes, shared_key].concat();

        // initialize HKDF with SHA-256 as the hash function
        let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0u8; 32]), &input_key_material); // 32 zeroed bytes as salt

        // derive 64 bytes for the output key (symmetric encryption + MAC key)
        let mut okm = vec![0u8; 64];
        hkdf.expand(SENDER_ID, &mut okm)
            .map_err(|_| anyhow!("Failed to derive key"))?;

        Ok(okm)
    }

    fn verify_hmac(&self, mac_key: &[u8], tag: &[u8], encrypted_message: &[u8]) -> Result<()> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        hmac::verify(&hmac_key, encrypted_message, tag).map_err(|_| anyhow!("Invalid HMAC"))
    }

    // Method to decrypt the AES-GCM encrypted message
    fn decrypt_message(&self, symmetric_key: &[u8], encrypted_message: &[u8]) -> Result<Vec<u8>> {
        //initialization vector IV is typically used in AES-GCM (Galois/Counter Mode) encryption for randomizing the encryption process.
        let iv = [0u8; 16];

        // extract the tag from the end of the encrypted message
        let tag = encrypted_message
            .get(encrypted_message.len() - 16..)
            .ok_or_else(|| anyhow!("failed to create ciphertext"))?;

        // decrypt the message using AES-256-CTR
        let cipher = Cipher::aes_256_ctr();
        let decrypted_data = decrypt_aead(
            cipher,
            symmetric_key,
            Some(&iv),
            &[],
            encrypted_message,
            tag,
        )?;

        Ok(decrypted_data)
    }
}
