# Secure Messaging System - Double Ratchet implementation

## This project implements a secure messaging system based on the Double Ratchet algorithm, inspired by modern end-to-end encrypted messaging protocols such as Signal and WhatsApp. The protocol combines Elliptic Curve Diffie-Hellman (ECDH) key exchange with symmetric key ratcheting to continuously evolve encryption keys and provide strong security guarantees. In addition to forward secrecy and break-in recovery, the system integrates an ElGamal public key encryption mechanism that enables a designated authority to decrypt message keys, demonstrating how lawful access models can be incorporated into end-to-end encrypted systems.

## Security Properties

- Forward Secrecy – past messages remain secure even if current keys are compromised  
- Break-in Recovery – security is restored after a ratchet step following compromise  
- Authenticated Encryption – AES-GCM ensures confidentiality and integrity  
- Replay Protection – duplicate messages are detected and rejected  
- Out-of-Order Handling – skipped message keys are stored and processed securely

## Cryptographic Primitives

- Elliptic Curve Diffie-Hellman (SECP384R1)
- HKDF (SHA-256)
- AES-GCM for authenticated encryption
- ECDSA for certificate verification

## Testing

The project includes a comprehensive unit test suite covering:

- Certificate verification
- Secure message exchange
- Government key decryption
- Replay attack detection
- Out-of-order message handling
- Multi-user communication scenarios
