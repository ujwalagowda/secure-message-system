/**
 * model package
 *
 * Contains JPA entity classes that map to MySQL database tables:
 *   - User.java       Maps to the `users` table
 *                     Fields: id, username, email, password, role,
 *                             public_key, private_key, created_at, enabled
 *
 *   - Message.java    Maps to the `messages` table
 *                     Fields: id, sender_id (FK), receiver_id (FK),
 *                             encrypted_message, created_at, status
 *
 * IMPORTANT:
 *   - private_key is stored in the database but NEVER returned through any API.
 *   - encrypted_message stores RSA ciphertext only; plaintext is never stored.
 *
 * These entity classes will be implemented in Phase 3.
 */
package com.securemsg.model;
