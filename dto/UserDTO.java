package com.securemsg.dto;

import com.securemsg.model.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * UserDTO — safe outbound representation of a User.
 *
 * Contains ONLY fields that are safe to expose through the REST API:
 *   id, username, email, role, enabled, createdAt, publicKey
 *
 * NEVER included:
 *   password   — never returned
 *   privateKey — never returned; used server-side only for RSA decryption
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

    private Long          id;
    private String        username;
    private String        email;
    private String        role;
    private boolean       enabled;
    private LocalDateTime createdAt;

    /**
     * RSA-2048 public key (Base64-encoded X.509 format).
     * Safe to expose — other users need it to encrypt messages for this user.
     * The corresponding private key is NEVER included here.
     */
    private String publicKey;

    /** Converts a User entity to a UserDTO, explicitly excluding privateKey. */
    public static UserDTO from(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole() != null ? user.getRole().name() : "USER")
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .publicKey(user.getPublicKey())   // safe — public key only
                // privateKey deliberately omitted
                .build();
    }
}
