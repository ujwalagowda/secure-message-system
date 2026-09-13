/**
 * crypto package
 *
 * Contains ALL RSA cryptographic operations for this project.
 * This is the only package where cryptographic code lives.
 *
 *   - RSAService.java     Responsible for:
 *                           1. RSA-2048 key-pair generation
 *                              (KeyPairGenerator.getInstance("RSA"))
 *                           2. Encoding public/private keys to Base64 strings
 *                              for database storage
 *                           3. Reconstructing PublicKey / PrivateKey objects
 *                              from stored Base64 strings
 *                           4. Encrypting plaintext using a recipient's public key
 *                              (Cipher.getInstance("RSA/ECB/PKCS1Padding"))
 *                           5. Decrypting ciphertext using a recipient's private key
 *                              (Cipher.getInstance("RSA/ECB/PKCS1Padding"))
 *
 * RSA is the ONLY cryptographic algorithm used in this project.
 * No AES, DES, 3DES, ECC, SHA-256, HMAC, bcrypt, or Argon2 is used here.
 *
 * RSAService will be implemented in Phase 3 (RSA Implementation phase).
 */
package com.securemsg.crypto;
