package com.securemsg.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * SendMessageRequest — inbound DTO for POST /api/messages/send
 *
 * Carries the data submitted when User A sends a message to User B.
 *
 * What happens after this DTO reaches MessageService:
 *   1. recipientId  → look up User B from the database
 *   2. content      → validate length against RSA-2048 OAEP limit (190 chars)
 *   3. User B's publicKey is fetched from the database
 *   4. RSAService.encrypt(content, userB.publicKey) produces ciphertext
 *   5. Only the ciphertext is stored — the original content is discarded
 *
 * Security:
 *   - The plaintext content field is used ONLY for encryption and is
 *     never stored in the database or logged.
 *   - Maximum length is enforced here by @Size AND again in MessageService
 *     before the RSA encryption call.
 */
@Data
public class SendMessageRequest {

    /**
     * Database ID of the intended recipient (User B).
     * Must be a positive long value referencing an existing user.
     */
    @NotNull(message = "Recipient ID is required")
    @Positive(message = "Recipient ID must be a positive number")
    private Long recipientId;

    /**
     * Plaintext message content to be encrypted.
     *
     * RSA-2048 with OAEP/SHA-256 padding limits the maximum plaintext to:
     *   256 − 2×32 − 2 = 190 bytes
     *
     * We enforce 190 characters here (1 ASCII/Latin character = 1 byte).
     * For messages with multi-byte UTF-8 characters the byte limit applies,
     * so users should keep messages shorter for non-ASCII text.
     *
     * This content is NEVER stored. Only the encrypted ciphertext is persisted.
     */
    @NotBlank(message = "Message content cannot be empty")
    @Size(max = 190, message = "Message exceeds RSA-2048 limit of 190 characters")
    private String content;
}
