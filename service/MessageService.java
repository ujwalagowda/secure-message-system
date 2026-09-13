package com.securemsg.service;

import com.securemsg.crypto.RSAService;
import com.securemsg.dto.DecryptedMessageDTO;
import com.securemsg.dto.MessageDTO;
import com.securemsg.dto.SendMessageRequest;
import com.securemsg.exception.EncryptionException;
import com.securemsg.exception.MessageAccessDeniedException;
import com.securemsg.exception.UserNotFoundException;
import com.securemsg.model.Message;
import com.securemsg.model.User;
import com.securemsg.repository.MessageRepository;
import com.securemsg.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * MessageService
 *
 * Handles all secure message operations:
 *   1. sendMessage()      — encrypt with recipient's public key, store ciphertext
 *   2. getInbox()         — list messages received by the authenticated user
 *   3. getSentMessages()  — list messages sent by the authenticated user
 *   4. getMessageById()   — fetch a single message (sender or recipient only)
 *   5. decryptMessage()   — RSA-decrypt a message (recipient only)
 *
 * RSA flow recap:
 *   SEND:    plaintext → RSAService.encrypt(plaintext, recipient.publicKey)
 *                      → Base64 ciphertext stored in messages.encrypted_content
 *                      → plaintext discarded, never stored
 *
 *   DECRYPT: messages.encrypted_content (Base64 ciphertext)
 *                      → RSAService.decrypt(ciphertext, recipient.privateKey)
 *                      → plaintext returned to authenticated recipient only
 *                      → private key never leaves this service
 *
 * Security rules enforced here:
 *   - A user can only decrypt messages where they are the recipient.
 *   - A user can only view messages where they are sender or recipient.
 *   - Private keys are fetched from DB, used once, and not stored in any variable
 *     that outlives the method call.
 *   - Plaintext is never logged at any log level.
 *   - Private keys are never logged at any log level.
 */
@Service
@Transactional
public class MessageService {

    private static final Logger logger = LoggerFactory.getLogger(MessageService.class);

    private final MessageRepository messageRepository;
    private final UserRepository    userRepository;
    private final RSAService        rsaService;

    public MessageService(MessageRepository messageRepository,
                          UserRepository userRepository,
                          RSAService rsaService) {
        this.messageRepository = messageRepository;
        this.userRepository    = userRepository;
        this.rsaService        = rsaService;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. SEND MESSAGE
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encrypts a plaintext message with the recipient's RSA-2048 public key
     * and stores only the ciphertext in the database.
     *
     * Step-by-step:
     *   1. Resolve sender from their JWT username
     *   2. Resolve recipient from recipientId in the request
     *   3. Prevent a user from messaging themselves
     *   4. Validate recipient has an RSA public key (always true post-registration)
     *   5. RSAService.encrypt(plaintext, recipient.publicKey) → Base64 ciphertext
     *   6. Build and persist the Message entity with ciphertext only
     *   7. Return MessageDTO (ciphertext visible, plaintext gone)
     *
     * @param request      validated SendMessageRequest from controller
     * @param senderUsername username extracted from JWT by controller
     * @return MessageDTO of the saved message
     */
    public MessageDTO sendMessage(SendMessageRequest request, String senderUsername) {

        // 1. Load sender
        User sender = userRepository.findByUsername(senderUsername)
                .orElseThrow(() -> new UserNotFoundException(
                        "Sender not found: " + senderUsername));

        // 2. Load recipient
        User recipient = userRepository.findById(request.getRecipientId())
                .orElseThrow(() -> new UserNotFoundException(request.getRecipientId()));

        // 3. Prevent self-messaging
        if (sender.getId().equals(recipient.getId())) {
            throw new EncryptionException("You cannot send a message to yourself.");
        }

        // 4. Validate recipient has a public key
        if (recipient.getPublicKey() == null || recipient.getPublicKey().isBlank()) {
            throw new EncryptionException(
                    "Recipient does not have an RSA public key. " +
                    "They may need to re-register.");
        }

        // 5. RSA-encrypt the plaintext using the recipient's public key.
        //    After this call the plaintext is not referenced again.
        //    RSAService enforces the 190-character OAEP limit internally.
        String ciphertext = rsaService.encrypt(request.getContent(), recipient.getPublicKey());
        // Do NOT log request.getContent() or ciphertext

        // 6. Build and persist Message entity — ciphertext only, never plaintext
        Message message = Message.builder()
                .sender(sender)
                .recipient(recipient)
                .encryptedContent(ciphertext)
                .sentAt(LocalDateTime.now())
                .status(Message.MessageStatus.SENT)
                .build();

        Message saved = messageRepository.save(message);

        logger.info("Message sent: id={}, sender='{}', recipientId={}",
                saved.getId(), senderUsername, recipient.getId());

        // 7. Return DTO — encryptedContent (ciphertext) is included, plaintext is gone
        return MessageDTO.from(saved);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. INBOX  (received messages)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all messages received by the authenticated user, newest first.
     * Each MessageDTO contains the RSA ciphertext; no decryption happens here.
     * The frontend should display encryptedContent as "🔒 RSA-2048 Encrypted".
     *
     * @param username JWT username of the authenticated user
     * @return list of MessageDTOs addressed to this user
     */
    @Transactional(readOnly = true)
    public List<MessageDTO> getInbox(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        return messageRepository.findByRecipientOrderBySentAtDesc(user)
                .stream()
                .map(MessageDTO::from)
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. SENT MESSAGES
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns all messages sent by the authenticated user, newest first.
     * The sender can see the ciphertext they sent but CANNOT decrypt it —
     * decryption requires the recipient's private key, which the sender
     * does not have. This is a fundamental property of RSA asymmetric encryption.
     *
     * @param username JWT username of the authenticated user
     * @return list of MessageDTOs sent by this user
     */
    @Transactional(readOnly = true)
    public List<MessageDTO> getSentMessages(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        return messageRepository.findBySenderOrderBySentAtDesc(user)
                .stream()
                .map(MessageDTO::from)
                .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. GET SINGLE MESSAGE (metadata only, no decryption)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns a single message by ID.
     * The requesting user must be either the sender or the recipient.
     * The encryptedContent (ciphertext) is returned; decryption is a
     * separate explicit action via decryptMessage().
     *
     * @param messageId message primary key
     * @param username  JWT username of the requesting user
     * @return MessageDTO if the user is authorised to view it
     * @throws MessageAccessDeniedException if the user is not sender or recipient
     */
    @Transactional(readOnly = true)
    public MessageDTO getMessageById(Long messageId, String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        Message message = messageRepository
                .findByIdAndSenderOrRecipient(messageId, user)
                .orElseThrow(() -> new MessageAccessDeniedException(
                        "Message not found or you do not have permission to view it."));

        return MessageDTO.from(message);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. DECRYPT MESSAGE  (recipient only)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts a message using the recipient's RSA-2048 private key.
     *
     * Security checks performed before decryption:
     *   1. Message exists in the database
     *   2. The requesting user IS the recipient of this message
     *      (not just any authenticated user — specifically the recipient)
     *   3. Recipient has a private key stored (always true post-registration)
     *
     * Decryption flow:
     *   messages.encrypted_content  (Base64 ciphertext from DB)
     *     → RSAService.decrypt(ciphertext, recipient.privateKey)
     *     → plaintext String
     *     → returned in DecryptedMessageDTO to the recipient only
     *
     * After this call:
     *   - Message status is updated to READ
     *   - The private key object goes out of scope (GC eligible)
     *   - The plaintext is in the returned DTO only — never stored or logged
     *
     * @param messageId message primary key
     * @param username  JWT username of the requesting user (must be recipient)
     * @return DecryptedMessageDTO containing the plaintext
     * @throws MessageAccessDeniedException if the user is not the recipient
     */
    public DecryptedMessageDTO decryptMessage(Long messageId, String username) {

        // 1. Load the authenticated user
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));

        // 2. Load the message — must exist and be accessible to this user
        Message message = messageRepository.findById(messageId)
                .orElseThrow(() -> new MessageAccessDeniedException(
                        "Message not found."));

        // 3. CRITICAL security check: only the RECIPIENT can decrypt.
        //    A sender cannot decrypt their own sent message because they
        //    do not have the recipient's private key — this is enforced both
        //    by this check AND by the fact that RSA decryption would fail
        //    anyway with the wrong private key.
        if (!message.getRecipient().getId().equals(user.getId())) {
            throw new MessageAccessDeniedException(
                    "Access denied: only the message recipient can decrypt this message.");
        }

        // 4. Validate private key is present
        if (user.getPrivateKey() == null || user.getPrivateKey().isBlank()) {
            throw new MessageAccessDeniedException(
                    "RSA private key not found for this account. " +
                    "Please re-register to generate a new key pair.");
        }

        // 5. RSA decryption using the recipient's private key.
        //    The private key string is passed directly to RSAService —
        //    it is not stored in any intermediate variable here.
        //    Do NOT log the result (plaintext).
        String plaintext = rsaService.decrypt(
                message.getEncryptedContent(),
                user.getPrivateKey()           // loaded from DB, used once, not re-stored
        );

        // 6. Mark message as READ now that it has been decrypted
        message.setStatus(Message.MessageStatus.READ);
        messageRepository.save(message);

        logger.info("Message decrypted: id={}, recipientUsername='{}'",
                messageId, username);
        // Do NOT log plaintext

        // 7. Build and return the response — plaintext included for recipient only
        return DecryptedMessageDTO.builder()
                .id(message.getId())
                .senderId(message.getSender().getId())
                .senderUsername(message.getSender().getUsername())
                .recipientId(message.getRecipient().getId())
                .recipientUsername(message.getRecipient().getUsername())
                .encryptedContent(message.getEncryptedContent())
                .decryptedContent(plaintext)       // never stored; only in this response
                .sentAt(message.getSentAt())
                .algorithm("RSA-2048 / OAEP with SHA-256")
                .build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. UNREAD COUNT  (helper for dashboard badge)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the number of unread (SENT, not yet decrypted) messages
     * for the authenticated user's inbox.
     *
     * @param username JWT username of the authenticated user
     * @return count of unread messages
     */
    @Transactional(readOnly = true)
    public long getUnreadCount(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + username));
        return messageRepository.countUnreadByRecipient(user, Message.MessageStatus.SENT);
    }
}
