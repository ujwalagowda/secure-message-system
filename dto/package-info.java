/**
 * dto package
 *
 * Contains Data Transfer Objects (DTOs) used for API request/response bodies.
 * DTOs decouple the API contract from the internal entity model.
 *
 * Request DTOs (inbound data from frontend):
 *   - RegisterRequest.java        username, email, password
 *   - LoginRequest.java           username, password
 *   - SendMessageRequest.java     receiverId, plaintext (max 200 chars)
 *
 * Response DTOs (outbound data to frontend):
 *   - AuthResponse.java           token, username, role
 *   - UserDTO.java                id, username, email, publicKey
 *                                 NOTE: private_key is NEVER included here
 *   - MessageDTO.java             id, senderUsername, receiverUsername,
 *                                 encryptedMessage, createdAt, status
 *   - DecryptedMessageDTO.java    id, senderUsername, decryptedContent,
 *                                 createdAt
 *
 * These classes will be implemented in Phase 3.
 */
package com.securemsg.dto;
