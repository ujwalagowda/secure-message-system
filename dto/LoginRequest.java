package com.securemsg.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * LoginRequest — inbound DTO for POST /api/auth/login
 *
 * Carries credentials submitted by a user trying to log in.
 * The usernameOrEmail field accepts either a username or an
 * email address — the service layer checks both.
 */
@Data
public class LoginRequest {

    /**
     * The user's username OR email address.
     * The service will try to find the user by username first,
     * then by email if no username match is found.
     */
    @NotBlank(message = "Username or email is required")
    private String usernameOrEmail;

    /**
     * The user's plain-text password.
     * Compared directly against the stored password
     * (plaintext comparison — college project scope).
     */
    @NotBlank(message = "Password is required")
    private String password;
}
