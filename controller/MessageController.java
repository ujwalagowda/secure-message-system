package com.securemsg.controller;

import com.securemsg.dto.DecryptedMessageDTO;
import com.securemsg.dto.MessageDTO;
import com.securemsg.dto.SendMessageRequest;
import com.securemsg.service.MessageService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * MessageController
 *
 * Handles all secure messaging HTTP requests.
 * Every endpoint requires a valid JWT token.
 *
 * The authenticated user's identity is extracted from the JWT via
 * @AuthenticationPrincipal — the controller never trusts any
 * identity supplied in the request body.
 *
 * Endpoints:
 *   POST /api/messages/send        — encrypt and send a message
 *   GET  /api/messages/inbox       — list received messages (ciphertext)
 *   GET  /api/messages/sent        — list sent messages
 *   GET  /api/messages/{id}        — get single message metadata
 *   GET  /api/messages/{id}/decrypt — decrypt a message (recipient only)
 *   GET  /api/messages/unread-count — inbox badge count
 *
 * Security:
 *   - All endpoints are protected by JwtAuthenticationFilter.
 *   - The controller extracts the username from Spring's SecurityContext
 *     via @AuthenticationPrincipal — never from user-supplied input.
 *   - Ownership enforcement (sender/recipient checks) is done in
 *     MessageService, not here.
 *   - No private key, password, or plaintext appears in any response
 *     except DecryptedMessageDTO returned by /decrypt (recipient only).
 */
@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private final MessageService messageService;

    public MessageController(MessageService messageService) {
        this.messageService = messageService;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /api/messages/send
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Sends an RSA-encrypted message to another user.
     *
     * The plaintext content in the request body is:
     *   1. Validated (not blank, max 190 chars)
     *   2. Encrypted with the recipient's RSA-2048 public key
     *   3. Stored as ciphertext only — plaintext is discarded
     *
     * Request headers:
     *   Authorization: Bearer <JWT>
     *
     * Request body:
     * {
     *   "recipientId" : 2,
     *   "content"     : "Hello Bob, this is a secret message!"
     * }
     *
     * Success — 201 Created:
     * {
     *   "id"               : 1,
     *   "senderId"         : 1,
     *   "senderUsername"   : "alice",
     *   "recipientId"      : 2,
     *   "recipientUsername": "bob",
     *   "encryptedContent" : "Base64ciphertext...",
     *   "sentAt"           : "2026-09-11T10:30:00",
     *   "status"           : "SENT"
     * }
     *
     * Error responses:
     *   400 — validation failure (blank content, content too long, null recipientId)
     *   404 — recipient not found
     *   500 — RSA encryption failed
     *
     * @param request     validated SendMessageRequest body
     * @param userDetails injected by Spring Security from the JWT
     * @return 201 Created with MessageDTO
     */
    @PostMapping("/send")
    public ResponseEntity<MessageDTO> sendMessage(
            @Valid @RequestBody SendMessageRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {

        MessageDTO dto = messageService.sendMessage(request, userDetails.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(dto);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/messages/inbox
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all messages received by the authenticated user, newest first.
     *
     * Each message shows the RSA ciphertext (encryptedContent).
     * The frontend should display it as "🔒 RSA-2048 Encrypted" until
     * the user explicitly calls /decrypt.
     *
     * Request headers:
     *   Authorization: Bearer <JWT>
     *
     * Success — 200 OK:
     * [
     *   {
     *     "id"               : 1,
     *     "senderId"         : 1,
     *     "senderUsername"   : "alice",
     *     "recipientId"      : 2,
     *     "recipientUsername": "bob",
     *     "encryptedContent" : "Base64ciphertext...",
     *     "sentAt"           : "2026-09-11T10:30:00",
     *     "status"           : "SENT"
     *   }
     * ]
     *
     * @param userDetails injected by Spring Security from the JWT
     * @return 200 OK with list of MessageDTOs
     */
    @GetMapping("/inbox")
    public ResponseEntity<List<MessageDTO>> getInbox(
            @AuthenticationPrincipal UserDetails userDetails) {

        List<MessageDTO> inbox = messageService.getInbox(userDetails.getUsername());
        return ResponseEntity.ok(inbox);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/messages/sent
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all messages sent by the authenticated user, newest first.
     *
     * Note: the sender CANNOT decrypt their own sent messages because
     * decryption requires the recipient's private key. This is a
     * fundamental property of RSA asymmetric encryption and demonstrates
     * why only the intended recipient can read the message.
     *
     * Request headers:
     *   Authorization: Bearer <JWT>
     *
     * @param userDetails injected by Spring Security from the JWT
     * @return 200 OK with list of MessageDTOs
     */
    @GetMapping("/sent")
    public ResponseEntity<List<MessageDTO>> getSentMessages(
            @AuthenticationPrincipal UserDetails userDetails) {

        List<MessageDTO> sent = messageService.getSentMessages(userDetails.getUsername());
        return ResponseEntity.ok(sent);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/messages/{id}
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns metadata and ciphertext for a single message.
     * The requesting user must be either the sender or the recipient.
     * No decryption happens here.
     *
     * Request headers:
     *   Authorization: Bearer <JWT>
     *
     * Success — 200 OK: MessageDTO
     *
     * Error responses:
     *   403 — user is not the sender or recipient of this message
     *   404 — message not found (returned as 403 to avoid ID enumeration)
     *
     * @param id          message primary key from URL path
     * @param userDetails injected by Spring Security from the JWT
     * @return 200 OK with MessageDTO
     */
    @GetMapping("/{id}")
    public ResponseEntity<MessageDTO> getMessageById(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {

        MessageDTO dto = messageService.getMessageById(id, userDetails.getUsername());
        return ResponseEntity.ok(dto);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/messages/{id}/decrypt
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts a message using the recipient's RSA-2048 private key.
     *
     * Only the intended recipient can call this endpoint successfully.
     * MessageService verifies recipient identity before decryption.
     *
     * RSA decryption flow (happens in MessageService → RSAService):
     *   Base64 ciphertext (from DB)
     *     → Base64.decode → byte[]
     *     → Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
     *     → cipher.init(DECRYPT_MODE, recipientPrivateKey)
     *     → cipher.doFinal(cipherBytes)
     *     → plaintext String returned in response
     *
     * The private key never leaves the server. The plaintext is returned
     * only in this response and is never stored.
     *
     * Request headers:
     *   Authorization: Bearer <JWT>   (must be the recipient's token)
     *
     * Success — 200 OK:
     * {
     *   "id"               : 1,
     *   "senderId"         : 1,
     *   "senderUsername"   : "alice",
     *   "recipientId"      : 2,
     *   "recipientUsername": "bob",
     *   "encryptedContent" : "Base64ciphertext...",
     *   "decryptedContent" : "Hello Bob, this is a secret message!",
     *   "sentAt"           : "2026-09-11T10:30:00",
     *   "algorithm"        : "RSA-2048 / OAEP with SHA-256"
     * }
     *
     * Error responses:
     *   403 — user is not the recipient of this message
     *   404 — message not found
     *   500 — RSA decryption failed (corrupted ciphertext or key)
     *
     * @param id          message primary key from URL path
     * @param userDetails injected by Spring Security from the JWT
     * @return 200 OK with DecryptedMessageDTO
     */
    @GetMapping("/{id}/decrypt")
    public ResponseEntity<DecryptedMessageDTO> decryptMessage(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails userDetails) {

        DecryptedMessageDTO dto = messageService.decryptMessage(id, userDetails.getUsername());
        return ResponseEntity.ok(dto);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /api/messages/unread-count
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the count of unread messages in the authenticated user's inbox.
     * Used by the frontend dashboard to display an inbox badge.
     *
     * Request headers:
     *   Authorization: Bearer <JWT>
     *
     * Success — 200 OK:
     * { "unreadCount": 3 }
     *
     * @param userDetails injected by Spring Security from the JWT
     * @return 200 OK with JSON object containing the unread count
     */
    @GetMapping("/unread-count")
    public ResponseEntity<Map<String, Long>> getUnreadCount(
            @AuthenticationPrincipal UserDetails userDetails) {

        long count = messageService.getUnreadCount(userDetails.getUsername());
        return ResponseEntity.ok(Map.of("unreadCount", count));
    }
}
