package com.securemsg.dto;

import com.securemsg.model.Message;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * MessageDTO — outbound DTO for message list responses.
 *
 * Returned by:
 *   GET /api/messages/inbox   — list of received messages
 *   GET /api/messages/sent    — list of sent messages
 *   GET /api/messages/{id}    — single message detail
 *
 * Security rules enforced in this DTO:
 *   - encryptedContent contains the RSA ciphertext exactly as stored in DB.
 *     It is safe to return — without the recipient's private key it is
 *     meaningless to anyone who intercepts it.
 *   - decryptedContent is always NULL in this DTO. Decrypted text is only
 *     returned in DecryptedMessageDTO via the explicit /decrypt endpoint.
 *   - No private key, no password, no sensitive user data is included.
 *
 * The frontend should display encryptedContent as "🔒 RSA-2048 Encrypted"
 * until the user explicitly requests decryption.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MessageDTO {

    /** Database primary key of this message. */
    private Long id;

    /** ID of the user who sent this message. */
    private Long senderId;

    /** Display username of the sender. */
    private String senderUsername;

    /** ID of the user this message was sent to. */
    private Long recipientId;

    /** Display username of the recipient. */
    private String recipientUsername;

    /**
     * RSA-2048 ciphertext — Base64-encoded.
     * Safe to expose: only the recipient's private key can decrypt it.
     * The frontend should treat this as opaque encrypted data.
     */
    private String encryptedContent;

    /** When the message was sent. */
    private LocalDateTime sentAt;

    /** SENT or READ */
    private String status;

    // ─────────────────────────────────────────────────────────
    // Static factory — builds a MessageDTO from a Message entity
    // ─────────────────────────────────────────────────────────

    /**
     * Converts a Message JPA entity into a MessageDTO.
     * Called by MessageService to avoid entity exposure to controllers.
     *
     * @param message the Message entity (sender and recipient must be loaded)
     * @return a safe, serialisable MessageDTO
     */
    public static MessageDTO from(Message message) {
        return MessageDTO.builder()
                .id(message.getId())
                .senderId(message.getSender().getId())
                .senderUsername(message.getSender().getUsername())
                .recipientId(message.getRecipient().getId())
                .recipientUsername(message.getRecipient().getUsername())
                .encryptedContent(message.getEncryptedContent())
                .sentAt(message.getSentAt())
                .status(message.getStatus().name())
                .build();
    }
}
