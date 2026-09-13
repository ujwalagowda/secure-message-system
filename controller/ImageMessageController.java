package com.securemsg.controller;

import com.securemsg.dto.ImageMessageDTO;
import com.securemsg.service.ImageMessageService;
import com.securemsg.service.ImageMessageService.DecryptedImage;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * ImageMessageController
 *
 * REST endpoints for hybrid-encrypted image messaging.
 * All endpoints require a valid JWT token.
 *
 * Identity is ALWAYS extracted from the JWT via @AuthenticationPrincipal —
 * never from any request parameter or body field.
 *
 * Endpoints:
 *   POST /api/images/send        — upload and encrypt an image for a recipient
 *   GET  /api/images/inbox       — list received image messages (metadata only)
 *   GET  /api/images/sent        — list sent image messages (metadata only)
 *   GET  /api/images/{id}/decrypt — decrypt and stream the image (recipient only)
 *   GET  /api/images/unread-count — count of unread image messages
 *
 * The decrypt endpoint streams raw image bytes directly as the HTTP response
 * body (not JSON). The browser can use the URL as an <img src=""> value.
 *
 * Encryption details (for the record):
 *   Send:
 *     imageBytes → AES-256-GCM → encryptedImageBytes (stored as LONGBLOB)
 *     aesKey     → RSA-2048-OAEP(recipientPublicKey) → encryptedAesKey (stored as TEXT)
 *   Decrypt:
 *     encryptedAesKey → RSA-2048-OAEP-decrypt(recipientPrivateKey) → aesKey
 *     encryptedImage  → AES-256-GCM-decrypt(aesKey, gcmIv) → imageBytes → streamed
 */
@RestController
@RequestMapping("/api/images")
public class ImageMessageController {

    private final ImageMessageService imageMessageService;

    public ImageMessageController(ImageMessageService imageMessageService) {
        this.imageMessageService = imageMessageService;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/images/send
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Uploads, validates, and hybrid-encrypts an image for a recipient.
     *
     * Multipart form fields:
     *   file        — the image file (required)
     *   recipientId — the recipient's user ID (required)
     *
     * Backend processing:
     *   1. Validate MIME type ∈ {image/jpeg, image/png, image/gif, image/webp}
     *   2. Validate extension ∈ {jpg, jpeg, png, gif, webp}
     *   3. Validate size ≤ 5 MB
     *   4. Sanitize filename (path traversal prevention)
     *   5. AES-256-GCM encrypt image bytes with random key+IV
     *   6. RSA-2048-OAEP encrypt AES key with recipient's public key
     *   7. Store ciphertext in image_messages table
     *
     * Request: multipart/form-data
     *   file=<image>
     *   recipientId=<long>
     *
     * Success — 201 Created: ImageMessageDTO (metadata only, no image bytes)
     * Errors:
     *   400 — invalid file type, too large, missing file, self-send
     *   401 — not authenticated
     *   404 — recipient not found
     *   500 — encryption failure
     */
    @PostMapping(value = "/send", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImageMessageDTO> sendImage(
            @RequestParam("file")        MultipartFile file,
            @RequestParam("recipientId") Long recipientId,
            @AuthenticationPrincipal     UserDetails userDetails) {

        ImageMessageDTO dto = imageMessageService.sendImage(
                file, recipientId, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/images/inbox
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all image messages received by the authenticated user, newest first.
     * Returns metadata DTOs only — no encrypted image bytes, no AES keys.
     *
     * The frontend uses this to display the inbox list with image badges.
     * Actual image retrieval requires a separate call to /decrypt.
     *
     * Success — 200 OK: List<ImageMessageDTO>
     */
    @GetMapping("/inbox")
    public ResponseEntity<List<ImageMessageDTO>> getInbox(
            @AuthenticationPrincipal UserDetails userDetails) {

        return ResponseEntity.ok(imageMessageService.getInbox(userDetails.getUsername()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/images/sent
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all image messages sent by the authenticated user, newest first.
     * Returns metadata DTOs only.
     *
     * Success — 200 OK: List<ImageMessageDTO>
     */
    @GetMapping("/sent")
    public ResponseEntity<List<ImageMessageDTO>> getSent(
            @AuthenticationPrincipal UserDetails userDetails) {

        return ResponseEntity.ok(imageMessageService.getSent(userDetails.getUsername()));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/images/{id}/decrypt
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts an image and streams the raw bytes to the authenticated recipient.
     *
     * This endpoint is the ONLY place where decryption occurs.
     * The service layer verifies the caller is the recipient before any
     * cryptographic operation.
     *
     * Decryption steps (in ImageMessageService):
     *   1. RSA-2048-OAEP decrypt(encryptedAesKey, recipientPrivateKey) → aesKey
     *   2. AES-256-GCM decrypt(encryptedImage, aesKey, gcmIv) → imageBytes
     *   3. GCM auth tag automatically verified — tampering caught here
     *   4. Mark message READ
     *
     * Response:
     *   - Content-Type: image/jpeg (or image/png etc., from stored mimeType)
     *   - Content-Disposition: inline; filename="..."
     *   - Body: raw image bytes
     *
     * The browser can use this URL directly as <img src="/api/images/{id}/decrypt">
     * with the Authorization header attached (via fetch + Blob URL on the frontend).
     *
     * Errors:
     *   401 — not authenticated
     *   403 — authenticated but not the recipient
     *   404 — image message not found
     *   500 — decryption failure (wrong key or tampered data)
     */
    @GetMapping("/{id}/decrypt")
    public ResponseEntity<byte[]> decryptImage(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {

        DecryptedImage result = imageMessageService.decryptImage(id, userDetails.getUsername());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(result.mimeType()));
        headers.set(HttpHeaders.CONTENT_DISPOSITION,
                "inline; filename=\"" + result.filename() + "\"");
        headers.setContentLength(result.imageBytes().length);

        return new ResponseEntity<>(result.imageBytes(), headers, HttpStatus.OK);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/images/unread-count
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the count of unread image messages for the authenticated user.
     * Used by the frontend inbox badge.
     *
     * Success — 200 OK: { "unreadCount": 2 }
     */
    @GetMapping("/unread-count")
    public ResponseEntity<Map<String, Long>> getUnreadCount(
            @AuthenticationPrincipal UserDetails userDetails) {

        long count = imageMessageService.getUnreadCount(userDetails.getUsername());
        return ResponseEntity.ok(Map.of("unreadCount", count));
    }
}
