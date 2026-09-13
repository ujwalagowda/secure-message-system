package com.securemsg.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Message — JPA entity mapped to the `messages` table in MySQL.
 *
 * Fields:
 *   id               — auto-generated primary key
 *   sender           — FK → users.id (who sent the message)
 *   recipient        — FK → users.id (who receives the message)
 *   encryptedContent — RSA-2048 ciphertext, Base64-encoded
 *                      plaintext is NEVER stored here
 *   sentAt           — timestamp of when the message was sent
 *   status           — SENT or READ
 *
 * Security rules:
 *   - encryptedContent holds only the RSA ciphertext produced by
 *     RSAService.encrypt(plaintext, recipientPublicKey).
 *   - The original plaintext message is discarded immediately after
 *     encryption and is never persisted anywhere.
 *   - Decryption happens at read time, server-side, inside
 *     MessageService.decryptMessage(), and is only available to
 *     the authenticated recipient.
 *
 * Relationship note:
 *   Both sender and recipient are ManyToOne associations to User.
 *   FetchType.LAZY avoids loading full User objects unless needed.
 *   RESTRICT prevents accidental deletion cascading to messages.
 */
@Entity
@Table(name = "messages")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Message {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The user who sent this message.
     * Many messages can have the same sender.
     * FK → users.id
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sender_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_message_sender"))
    private User sender;

    /**
     * The user who should receive (and can decrypt) this message.
     * Many messages can share the same recipient.
     * FK → users.id
     */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_message_recipient"))
    private User recipient;

    /**
     * RSA-2048 encrypted message content.
     *
     * Stored as a Base64-encoded string of the RSA ciphertext.
     * Encrypted using the recipient's public key.
     * Can only be decrypted using the recipient's private key.
     *
     * TEXT column — RSA-2048 ciphertext is always 256 bytes → Base64 ≈ 344 chars.
     *
     * IMPORTANT: The original plaintext message is NEVER stored.
     * Only this ciphertext exists in the database.
     */
    @Column(name = "encrypted_content", columnDefinition = "TEXT", nullable = false)
    private String encryptedContent;

    /**
     * Timestamp of when the message was sent.
     * Set by MessageService before saving. Not updatable.
     */
    @Column(name = "sent_at", nullable = false, updatable = false)
    private LocalDateTime sentAt;

    /**
     * Message delivery/read status.
     * SENT  — message delivered to DB, recipient has not yet decrypted it.
     * READ  — recipient has successfully decrypted the message at least once.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private MessageStatus status;

    /**
     * Status enum for message lifecycle.
     */
    public enum MessageStatus {
        SENT,
        READ
    }
}
