package com.securemsg.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * ImageMessage — JPA entity mapped to the `image_messages` table in MySQL.
 *
 * Stores a hybrid-encrypted image message:
 *   - The image itself is AES-256-GCM encrypted (encryptedImage LONGBLOB)
 *   - The AES key is RSA-2048-OAEP encrypted (encryptedAesKey TEXT, Base64)
 *   - The GCM IV is stored in plaintext (not secret, just unique — Base64)
 *
 * This table is COMPLETELY SEPARATE from the existing `messages` table.
 * The existing Message entity and messages table are NOT modified.
 *
 * Hybrid encryption flow:
 *   SEND:
 *     plainImageBytes
 *       → AES-256-GCM(randomAesKey, randomIV) → encryptedImage
 *       → RSA-2048-OAEP(recipient.publicKey, aesKeyBytes) → encryptedAesKey
 *       → store {encryptedImage, encryptedAesKey, gcmIv, metadata}
 *
 *   DECRYPT (recipient only):
 *     encryptedAesKey
 *       → RSA-2048-OAEP decrypt(recipient.privateKey) → aesKeyBytes
 *       → AES-256-GCM decrypt(aesKeyBytes, gcmIv, encryptedImage) → plainImageBytes
 *
 * Security rules:
 *   - encryptedAesKey: RSA ciphertext — useless without recipient's private key
 *   - encryptedImage: AES-GCM ciphertext — useless without AES key
 *   - Neither AES key nor RSA private key is ever stored in plaintext
 *   - originalFilename is SERVER-SANITIZED before storage
 *     (client-supplied filename is never trusted)
 */
@Entity
@Table(name = "image_messages")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ImageMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The user who sent this image message.  FK → users.id */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "sender_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_imgmsg_sender"))
    private User sender;

    /** The intended recipient.  FK → users.id */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false,
                foreignKey = @ForeignKey(name = "fk_imgmsg_recipient"))
    private User recipient;

    /**
     * AES-256-GCM encrypted image bytes, including the 128-bit GCM auth tag.
     *
     * LONGBLOB supports up to 4 GB — more than enough for the 5 MB limit.
     * The GCM auth tag (last 16 bytes) allows tampering detection on decrypt.
     *
     * NEVER stored in plaintext. AES-encrypted with a per-image random key.
     */
    @Lob
    @Column(name = "encrypted_image", nullable = false, columnDefinition = "LONGBLOB")
    private byte[] encryptedImage;

    /**
     * RSA-2048-OAEP ciphertext of the AES key, Base64-encoded.
     *
     * Produced by: RSAService.encrypt(Base64(aesKeyBytes), recipient.publicKey)
     * Can only be reversed by: RSAService.decrypt(encryptedAesKey, recipient.privateKey)
     *
     * Stored as TEXT (RSA-2048 ciphertext is always 256 bytes → Base64 ≈ 344 chars).
     */
    @Column(name = "encrypted_aes_key", columnDefinition = "TEXT", nullable = false)
    private String encryptedAesKey;

    /**
     * AES-GCM IV (nonce), Base64-encoded.
     *
     * 96 bits (12 bytes) per GCM recommendation.
     * NOT a secret — must be unique per encryption, but can be stored openly.
     * Required for decryption alongside the AES key.
     */
    @Column(name = "gcm_iv", nullable = false, length = 32)
    private String gcmIv;

    /**
     * Server-sanitized original filename for display purposes only.
     *
     * The client-supplied filename is NEVER used for file system paths.
     * Only alphanumeric chars, hyphens, underscores, and a single dot are kept.
     * Stored purely so the recipient knows what they are receiving.
     */
    @Column(name = "original_filename", nullable = false, length = 255)
    private String originalFilename;

    /**
     * MIME type of the original image, validated server-side.
     * Allowed values: image/jpeg, image/png, image/gif, image/webp
     */
    @Column(name = "mime_type", nullable = false, length = 50)
    private String mimeType;

    /**
     * File size of the ORIGINAL (pre-encryption) image in bytes.
     * Used for display in the UI (e.g. "2.4 MB").
     * Validated to be ≤ 5 MB before encryption.
     */
    @Column(name = "file_size", nullable = false)
    private long fileSize;

    /** Timestamp of when the image message was sent. */
    @Column(name = "sent_at", nullable = false, updatable = false)
    private LocalDateTime sentAt;

    /** SENT = delivered and not yet decrypted.  READ = recipient decrypted it. */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private ImageMessageStatus status;

    /** Status lifecycle for image messages (mirrors Message.MessageStatus). */
    public enum ImageMessageStatus {
        SENT,
        READ
    }
}
