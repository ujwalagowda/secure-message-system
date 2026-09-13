package com.securemsg.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DecryptedMessageDTO — outbound DTO for a successfully decrypted message.
 *
 * Returned ONLY by:
 *   GET /api/messages/{id}/decrypt
 *
 * This endpoint is restricted to the authenticated recipient only.
 * MessageService verifies that the requesting user is the recipient
 * before RSA decryption is attempted.
 *
 * Security rules:
 *   - decryptedContent contains the original plaintext — it is returned
 *     only to the authenticated recipient in a single response and is
 *     never stored in the database.
 *   - No private key is included. The private key is loaded server-side,
 *     used for one decryption call, and immediately discarded.
 *   - The encryptedContent is also included so the frontend can show
 *     both forms (ciphertext → plaintext) for educational demonstration.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DecryptedMessageDTO {

    /** Database primary key of this message. */
    private Long id;

    /** ID of the user who originally sent this message. */
    private Long senderId;

    /** Display username of the sender. */
    private String senderUsername;

    /** ID of the recipient (the currently authenticated user). */
    private Long recipientId;

    /** Display username of the recipient. */
    private String recipientUsername;

    /**
     * The original RSA ciphertext (Base64) — included for educational
     * demonstration so the UI can show the before/after comparison.
     * Safe to expose: useless without the private key.
     */
    private String encryptedContent;

    /**
     * The decrypted plaintext — the original message content.
     *
     * IMPORTANT:
     *   - This field is populated server-side by RSAService.decrypt()
     *     using the recipient's private key.
     *   - It is returned to the recipient in this response only.
     *   - It is NEVER stored in the database.
     *   - It is NEVER logged.
     */
    private String decryptedContent;

    /** When the message was originally sent. */
    private LocalDateTime sentAt;

    /** Algorithm label for UI display: "RSA-2048 / OAEP" */
    private String algorithm;
}
