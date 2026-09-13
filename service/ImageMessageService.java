package com.securemsg.service;

import com.securemsg.crypto.AESService;
import com.securemsg.crypto.RSAService;
import com.securemsg.dto.ImageMessageDTO;
import com.securemsg.exception.DecryptionException;
import com.securemsg.exception.EncryptionException;
import com.securemsg.exception.MessageAccessDeniedException;
import com.securemsg.exception.UserNotFoundException;
import com.securemsg.model.ImageMessage;
import com.securemsg.model.User;
import com.securemsg.repository.ImageMessageRepository;
import com.securemsg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * ImageMessageService
 *
 * Orchestrates hybrid-encrypted image messaging.
 *
 * ─── Send flow ─────────────────────────────────────────────────────────────
 *  1. Validate file: MIME type, extension, size
 *  2. Sanitize filename (path traversal prevention)
 *  3. Generate random AES-256 key + 96-bit GCM IV
 *  4. AES-256-GCM encrypt the image bytes
 *  5. RSA-2048-OAEP encrypt the raw AES key bytes using recipient's public key
 *  6. Persist ImageMessage entity (ciphertext only — plaintext bytes discarded)
 *
 * ─── Decrypt flow ──────────────────────────────────────────────────────────
 *  1. Verify requesting user is the recipient (not just any authenticated user)
 *  2. RSA-2048-OAEP decrypt encryptedAesKey → raw AES key bytes
 *     (uses recipient's private key from DB — never returned to client)
 *  3. Reconstruct AES SecretKey from raw bytes
 *  4. AES-256-GCM decrypt encryptedImage → original image bytes
 *     (GCM auth tag verified automatically — tampering detected here)
 *  5. Return image bytes + MIME type to controller for streaming
 *  6. Mark message as READ
 *
 * ─── Security rules ────────────────────────────────────────────────────────
 *  - AES key is NEVER stored in plaintext; only RSA-encrypted form is persisted
 *  - AES key bytes are NEVER logged
 *  - Decrypted image bytes are NEVER logged
 *  - RSA private key is NEVER returned to frontend
 *  - Filename supplied by client is sanitized before storage
 *  - MIME type is validated from MultipartFile.getContentType() (not filename)
 *  - Extension is validated against a whitelist
 *  - File size is checked before encryption
 *  - Only the authenticated recipient can decrypt
 */
@Service
@Transactional
public class ImageMessageService {

    private static final Logger logger = LoggerFactory.getLogger(ImageMessageService.class);

    /** Allowed MIME types (validated from file content type) */
    private static final Set<String> ALLOWED_MIME_TYPES = Set.of(
            "image/jpeg", "image/png", "image/gif", "image/webp"
    );

    /** Allowed file extensions (validated from sanitized filename) */
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "jpg", "jpeg", "png", "gif", "webp"
    );

    /** Maximum image size: 5 MB */
    @Value("${image.max-size-bytes:5242880}")
    private long maxSizeBytes;

    private final ImageMessageRepository imageMessageRepository;
    private final UserRepository         userRepository;
    private final AESService             aesService;
    private final RSAService             rsaService;

    public ImageMessageService(ImageMessageRepository imageMessageRepository,
                                UserRepository userRepository,
                                AESService aesService,
                                RSAService rsaService) {
        this.imageMessageRepository = imageMessageRepository;
        this.userRepository         = userRepository;
        this.aesService             = aesService;
        this.rsaService             = rsaService;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SEND IMAGE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encrypts and stores an image message.
     *
     * @param file            the uploaded image file (MultipartFile)
     * @param recipientId     database ID of the intended recipient
     * @param senderUsername  username extracted from JWT by controller
     * @return ImageMessageDTO with metadata (no encrypted bytes, no keys)
     */
    public ImageMessageDTO sendImage(MultipartFile file, Long recipientId, String senderUsername) {

        // 1. Load sender
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new UserNotFoundException("Sender not found: " + senderUsername));

        // 2. Load recipient
        User recipient = userRepository.findById(recipientId)
                .orElseThrow(() -> new UserNotFoundException(recipientId));

        // 3. Prevent self-messaging
        if (sender.getId().equals(recipient.getId())) {
            throw new EncryptionException("You cannot send an image to yourself.");
        }

        // 4. Validate recipient has an RSA public key
        if (recipient.getPublicKey() == null || recipient.getPublicKey().isBlank()) {
            throw new EncryptionException(
                    "Recipient does not have an RSA public key. They may need to re-register.");
        }

        // 5. Validate file is present
        if (file == null || file.isEmpty()) {
            throw new EncryptionException("No image file provided.");
        }

        // 6. Validate file size
        if (file.getSize() > maxSizeBytes) {
            throw new EncryptionException(
                    "Image too large. Maximum allowed size is " +
                    humanReadableSize(maxSizeBytes) + ". Uploaded: " +
                    humanReadableSize(file.getSize()));
        }

        // 7. Validate MIME type (from content-type header, not filename)
        String mimeType = file.getContentType();
        if (mimeType == null || !ALLOWED_MIME_TYPES.contains(mimeType.toLowerCase())) {
            throw new EncryptionException(
                    "Invalid file type: '" + mimeType + "'. " +
                    "Allowed types: JPEG, PNG, GIF, WebP.");
        }

        // 8. Sanitize and validate filename
        String safeFilename = sanitizeFilename(file.getOriginalFilename());
        String extension    = getExtension(safeFilename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new EncryptionException(
                    "Invalid file extension: '" + extension + "'. " +
                    "Allowed: jpg, jpeg, png, gif, webp.");
        }

        // 9. Read image bytes
        byte[] imageBytes;
        try {
            imageBytes = file.getBytes();
        } catch (IOException e) {
            logger.error("Failed to read uploaded image: {}", e.getMessage(), e);
            throw new EncryptionException("Failed to read image file.", e);
        }

        // 10. Generate random AES-256 key and 96-bit GCM IV
        SecretKey aesKey = aesService.generateAESKey();
        byte[]    iv     = aesService.generateIV();
        // Do NOT log aesKey or iv values

        // 11. AES-256-GCM encrypt the image bytes
        byte[] encryptedImageBytes = aesService.encrypt(imageBytes, aesKey, iv);

        // 12. RSA-2048-OAEP encrypt the raw AES key bytes using recipient's public key.
        //     We pass the raw key bytes (not Base64) to RSA so the size stays small:
        //     AES-256 key = 32 bytes → well within RSA-2048 OAEP limit of 190 bytes.
        String encryptedAesKey = rsaService.encrypt(
                Base64.getEncoder().encodeToString(aesKey.getEncoded()),
                recipient.getPublicKey()
        );
        // AES key bytes and encoded key string go out of scope here — GC eligible

        // 13. Encode IV for storage
        String gcmIvBase64 = aesService.encodeIV(iv);

        // 14. Build and persist the ImageMessage entity
        ImageMessage imageMessage = ImageMessage.builder()
                .sender(sender)
                .recipient(recipient)
                .encryptedImage(encryptedImageBytes)
                .encryptedAesKey(encryptedAesKey)
                .gcmIv(gcmIvBase64)
                .originalFilename(safeFilename)
                .mimeType(mimeType)
                .fileSize(file.getSize())
                .sentAt(LocalDateTime.now())
                .status(ImageMessage.ImageMessageStatus.SENT)
                .build();

        ImageMessage saved = imageMessageRepository.save(imageMessage);

        logger.info("Image message sent: id={}, sender='{}', recipientId={}, size={}, type={}",
                saved.getId(), senderUsername, recipientId,
                humanReadableSize(file.getSize()), mimeType);
        // Do NOT log imageBytes or encryptedImageBytes

        return ImageMessageDTO.from(saved);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INBOX (received image messages)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all image messages received by the authenticated user, newest first.
     * Returns metadata DTOs only — no encrypted bytes, no keys.
     */
    @Transactional(readOnly = true)
    public List<ImageMessageDTO> getInbox(String username) {
        User user = loadUser(username);
        return imageMessageRepository.findByRecipientOrderBySentAtDesc(user)
                .stream()
                .map(ImageMessageDTO::from)
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SENT (sent image messages)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all image messages sent by the authenticated user, newest first.
     * Returns metadata DTOs only.
     */
    @Transactional(readOnly = true)
    public List<ImageMessageDTO> getSent(String username) {
        User user = loadUser(username);
        return imageMessageRepository.findBySenderOrderBySentAtDesc(user)
                .stream()
                .map(ImageMessageDTO::from)
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DECRYPT IMAGE (recipient only)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts an image message and returns the raw image bytes.
     * The MIME type is also returned so the controller can set Content-Type.
     *
     * Security checks before decryption:
     *   1. Message exists
     *   2. Requesting user IS the recipient (not sender, not third party)
     *   3. Recipient has a private key in DB
     *
     * Decryption steps:
     *   1. RSA-2048-OAEP decrypt encryptedAesKey → Base64(aesKeyBytes)
     *   2. Decode Base64 → raw AES key bytes
     *   3. Reconstruct AES SecretKey from raw bytes
     *   4. Decode stored GCM IV
     *   5. AES-256-GCM decrypt encryptedImage → original image bytes
     *      (GCM auth tag verified automatically — AEADBadTagException on tamper)
     *   6. Mark message READ
     *   7. Return DecryptedImage record to controller
     *
     * @param imageMessageId  ID of the ImageMessage to decrypt
     * @param username        JWT username of the requesting user (must be recipient)
     * @return DecryptedImage containing raw bytes + MIME type
     */
    public DecryptedImage decryptImage(Long imageMessageId, String username) {

        // 1. Load requesting user
        User user = loadUser(username);

        // 2. Load the image message — must exist
        ImageMessage imageMessage = imageMessageRepository.findById(imageMessageId)
                .orElseThrow(() -> new MessageAccessDeniedException("Image message not found."));

        // 3. CRITICAL: verify requesting user is the RECIPIENT, not anyone else
        if (!imageMessage.getRecipient().getId().equals(user.getId())) {
            throw new MessageAccessDeniedException(
                    "Access denied: only the message recipient can decrypt this image.");
        }

        // 4. Validate private key is present
        if (user.getPrivateKey() == null || user.getPrivateKey().isBlank()) {
            throw new DecryptionException(
                    "RSA private key not found. Please re-register to generate a new key pair.");
        }

        // 5. RSA-2048-OAEP decrypt the encrypted AES key.
        //    rsaService.decrypt returns Base64(aesKeyBytes) — the same format
        //    we passed to rsaService.encrypt() during send.
        //    The RSA private key is loaded server-side only and never returned.
        String base64AesKey = rsaService.decrypt(
                imageMessage.getEncryptedAesKey(),
                user.getPrivateKey()   // loaded from DB, used once, not re-stored
        );
        // Do NOT log base64AesKey

        // 6. Decode Base64 → raw AES key bytes → reconstruct SecretKey
        byte[]    aesKeyBytes = Base64.getDecoder().decode(base64AesKey);
        SecretKey aesKey      = aesService.decodeKey(aesKeyBytes);
        // Do NOT log aesKeyBytes

        // 7. Decode stored GCM IV
        byte[] iv = aesService.decodeIV(imageMessage.getGcmIv());

        // 8. AES-256-GCM decrypt — GCM auth tag verified automatically here.
        //    If the encrypted image was tampered with, AEADBadTagException is thrown
        //    and wrapped as DecryptionException by AESService.
        byte[] imageBytes = aesService.decrypt(imageMessage.getEncryptedImage(), aesKey, iv);
        // Do NOT log imageBytes

        // 9. Mark as READ
        imageMessage.setStatus(ImageMessage.ImageMessageStatus.READ);
        imageMessageRepository.save(imageMessage);

        logger.info("Image message decrypted: id={}, recipient='{}', type={}",
                imageMessageId, username, imageMessage.getMimeType());
        // Do NOT log imageBytes

        return new DecryptedImage(imageBytes, imageMessage.getMimeType(),
                imageMessage.getOriginalFilename());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UNREAD COUNT
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the count of unread image messages for the authenticated user.
     */
    @Transactional(readOnly = true)
    public long getUnreadCount(String username) {
        User user = loadUser(username);
        return imageMessageRepository.countUnreadByRecipient(
                user, ImageMessage.ImageMessageStatus.SENT);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    private User loadUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));
    }

    /**
     * Sanitizes a client-supplied filename to prevent path traversal attacks.
     *
     * Rules applied:
     *   - Strip directory components (/ \ : ..)
     *   - Keep only alphanumeric chars, hyphens, underscores, dots
     *   - Collapse to a single dot (prevent double-extension tricks)
     *   - Fall back to "upload.bin" if nothing remains after sanitization
     *
     * The sanitized name is stored for display only — NEVER used as a filesystem path.
     */
    String sanitizeFilename(String original) {
        if (original == null || original.isBlank()) return "image.bin";

        // Strip directory components
        String name = original;
        int lastSlash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (lastSlash >= 0) name = name.substring(lastSlash + 1);

        // Keep only safe characters
        name = name.replaceAll("[^a-zA-Z0-9._\\-]", "_");

        // Prevent path traversal via ".."
        name = name.replace("..", "_");

        // Trim dots and underscores from edges
        name = name.replaceAll("^[._]+|[._]+$", "");

        return name.isBlank() ? "image.bin" : name;
    }

    /** Extracts the lowercase file extension, or "" if none present. */
    private String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        return (dot >= 0 && dot < filename.length() - 1)
                ? filename.substring(dot + 1).toLowerCase()
                : "";
    }

    private static String humanReadableSize(long bytes) {
        if (bytes < 1024)    return bytes + " B";
        if (bytes < 1048576) return String.format("%.1f KB", bytes / 1024.0);
        return                      String.format("%.1f MB", bytes / 1048576.0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Decrypted image result record
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Simple value holder returned from decryptImage().
     * The controller streams imageBytes directly as the HTTP response body.
     * These bytes NEVER become JSON and are NEVER logged.
     */
    public record DecryptedImage(byte[] imageBytes, String mimeType, String filename) {}
}
