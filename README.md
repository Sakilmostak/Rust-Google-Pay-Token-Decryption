# Google Pay Token Decryption (Rust Implementation) 🔐

[![Rust Version](https://img.shields.io/badge/rust-1.60%2B-orange)](https://www.rust-lang.org/)

A Rust implementation for decrypting and verifying Google Pay payment tokens according to 
[Google's encryption specifications](https://developers.google.com/pay/api/web/guides/resources/payment-data-cryptography).

## 📱 About Google Pay & Tokenization

**Google Pay** is a digital wallet platform that enables users to:
- Store payment methods securely
- Make contactless payments
- Complete in-app/online purchases

**Tokenization** is the security process that:
1. Replaces sensitive card details with a unique token
2. This token is worthless if intercepted
3. The actual payment details never touch merchant servers

## 🛡️ Cryptographic Process Flow

```plaintext
         [Encrypted Token]
               |
        1. Parse Structure
               |
        2. Verify Signature
               |
        3. Decrypt Ciphertext
```

## 🚀 Getting Started

```bash
  # Clone repository
  git clone https://github.com/Sakilmostak/Rust-Google-Pay-Token-Decryption.git
  cd google-pay-decryption
  
  # Run the project
  cargo run
```
The decrypted token would be printed in the terminal
  
