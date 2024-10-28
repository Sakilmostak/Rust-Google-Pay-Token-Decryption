mod helper;

fn main() -> Result<(), helper::GooglePayError> {
    // Example initialization
    let root_signing_keys = vec![serde_json::json!({
        "keyValue": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==",
        "keyExpiration": "32506264800000",
        "protocolVersion": "ECv2",
    })]; // Initialize with real root keys
    let recipient_id = "merchant:12345678901234567890".to_string();
    let private_key = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCPSuFr4iSIaQprjjchHPyDu2NXFe0vDBoTpPkYaK9dehRANCAATnaFz/vQKuO90pxsINyVNWojabHfbx9qIJ6uD7Q7ZSxmtyo/Ez3/o2kDT8g0pIdyVIYktCsq65VoQIDWSh2Bdm".as_bytes(); // Insert private key bytes here

    // Create decryptor instance
    let decryptor =
        helper::GooglePayTokenDecryptor::new(root_signing_keys, recipient_id, private_key)?;

    // Placeholder encrypted data (to be replaced with actual data)
    let encrypted_data = r#"{
        "signature": "MEYCIQCbtFh9UIf1Ty3NKZ2z0ZmL0SHwR30uiRGuRXk9ghpyrwIhANiZQ0Df6noxkQ6M652PcIPkk2m1PQhqiq4UhzvPQOYf",
        "intermediateSigningKey": {
            "signedKey": "{\"keyValue\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/1+3HBVSbdv+j7NaArdgMyoSAM43yRydzqdg1TxodSzA96Dj4Mc1EiKroxxunavVIvdxGnJeFViTzFvzFRxyCw==\",\"keyExpiration\":\"1879409613939\"}",
            "signatures": [
                "MEQCIFBle+JsfsovRBeoFEYKWFAeBYFAhq0S+GtusiosjV4lAiAGcK9qfVpnqG6Hw8cbGBQ79beiAs6IIkBxBfeKDBR+kA=="
            ]
        },
        "protocolVersion": "ECv2",
        "signedMessage": "{\"encryptedMessage\":\"PeYi+ZnJs1Gei1dSOkItdfFG8Y81FvEI7dHE0sSrSU6OPnndftV/qDbbmXHmppoyP/2lhF+XsH93qzD3u46BRnxxPtetzGT0533rIraskTj8SZ6FVYY1Opfo7FECGk57FfF8aDaCSOoyTh1k0v6wdxVwEVvWqG1T/ij+u2KWOw5G1WSB/RVicni0Az13ModYb0KMdMws1USKlWxBfKU5PtxibVx4fZ95HYQ82qgHlV4ToKaUY7YWud1iEspmFsBMk0nh4t1hVxRzsxKUjMV1915qD5yq7k5n9YPao2mR9NJgLPDktsc4uf9bszzvnqhz3T1YID43QwX16yCyn/YxNVe3dJ1+S+BGyJ+vyKXp+Zh4SlIua2NFLwnR06Es3Kvl6LlOGasoPC/tMAWYLQlGsl+vHK3mrMZjC6KbOsXg+2mrlZwL+QOt3ih2jIPe\",\"ephemeralPublicKey\":\"BD6pQKpy7yDebAX4qV0u/AfMYNQhOD+teyoa/5SsxwTGCoC1ZKHxNMb5BXvRmBcYGPNTx8+fAkEwzJ8GqbX/Q7E=\",\"tag\":\"8gFteCvCuamX1RmL7ORdHqleyBf0N55OfAs80RYGgwc=\"}"
    }"#;

    // Attempt to decrypt
    match decryptor.decrypt_token(encrypted_data, true) {
        Ok(decrypted) => println!("Decrypted data: {:?}", decrypted),
        Err(e) => eprintln!("Decryption failed: {:?}", e),
    }

    Ok(())
}
