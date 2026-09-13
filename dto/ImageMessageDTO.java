package com.securemsg.dto;

import com.securemsg.model.ImageMessage;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * ImageMessageDTO — safe outbound metadata DTO for image messages.
 *
 * Used by:
 *   GET /api/images/inbox    — list received image messages
 *   GET /api/images/sent     — list sent image messages
 *
 * Security rules:
 *   - encryptedImage bytes are NEVER included here (would be huge and useless)
 *   - encryptedAesKey is NEVER included (would leak the RSA-encrypted AES key)
 *   - gcmIv is NEVER included (not needed by frontend for listing)
 *   - RSA private key is NEVER included anywhere
 *
 * The frontend uses this DTO to display inbox/sent lists.
 * Actual image retrieval happens only via GET /api/images/{id}/decrypt
 * which streams the decrypted image bytes directly as HTTP response body
 * (not as JSON — the browser renders it as an <img> src).
 *
 * messageType = "IMAGE" allows the frontend to distinguish image messages
 * from text messages when both are displayed in a unified inbox view.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ImageMessageDTO {

    private Long          id;
    private Long          senderId;
    private String        senderUsername;
    private Long          recipientId;
    private String        recipientUsername;

    /** Always "IMAGE" — lets frontend distinguish from text MessageDTO */
    private String        messageType;

    /** Server-sanitized filename for display only */
    private String        originalFilename;

    /** e.g. "image/jpeg" */
    private String        mimeType;

    /** Pre-encryption file size in bytes */
    private long          fileSize;

    private LocalDateTime sentAt;

    /** "SENT" or "READ" */
    private String        status;

    /** Human-readable file size, e.g. "2.4 MB" */
    private String        fileSizeDisplay;

    /** Static factory — converts entity to safe DTO */
    public static ImageMessageDTO from(ImageMessage m) {
        return ImageMessageDTO.builder()
                .id(m.getId())
                .senderId(m.getSender().getId())
                .senderUsername(m.getSender().getUsername())
                .recipientId(m.getRecipient().getId())
                .recipientUsername(m.getRecipient().getUsername())
                .messageType("IMAGE")
                .originalFilename(m.getOriginalFilename())
                .mimeType(m.getMimeType())
                .fileSize(m.getFileSize())
                .fileSizeDisplay(humanReadableSize(m.getFileSize()))
                .sentAt(m.getSentAt())
                .status(m.getStatus().name())
                .build();
    }

    /** Formats bytes into a human-readable string: 1024 → "1.0 KB" */
    private static String humanReadableSize(long bytes) {
        if (bytes < 1024)       return bytes + " B";
        if (bytes < 1048576)    return String.format("%.1f KB", bytes / 1024.0);
        return                         String.format("%.1f MB", bytes / 1048576.0);
    }
}
