package com.securemsg.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * RegisterRequest — inbound DTO for POST /api/auth/register
 *
 * Carries the data a new user submits when creating an account.
 * Validation annotations are enforced by Spring's @Valid in the controller.
 *
 * Fields deliberately excluded:
 *   - role      → always defaults to USER; client cannot choose
 *   - enabled   → always defaults to true on registration
 *   - publicKey / privateKey → generated server-side in Phase 4
 */
@Data
public class RegisterRequest {

    /**
     * Desired username.
     * Must be 3–50 characters and cannot be blank.
     * Uniqueness is checked in UserService against the database.
     */
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    /**
     * Email address.
     * Must be a valid email format and cannot be blank.
     * Uniqueness is checked in UserService against the database.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    @Size(max = 100, message = "Email must not exceed 100 characters")
    private String email;

    /**
     * Password.
     * Must be 6–255 characters.
     * Stored as plaintext — deliberate simplification for this
     * college project to avoid introducing a second cryptographic
     * algorithm (e.g. bcrypt) outside the RSA-only scope.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 255, message = "Password must be between 6 and 255 characters")
    private String password;
}
