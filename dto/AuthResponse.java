package com.securemsg.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AuthResponse — outbound DTO for both:
 *   POST /api/auth/register
 *   POST /api/auth/login
 *
 * Returned to the frontend after a successful registration or login.
 * The frontend stores the token in localStorage and sends it in the
 * Authorization header on subsequent requests:
 *   Authorization: Bearer <token>
 *
 * Fields deliberately excluded:
 *   - password    → never returned
 *   - privateKey  → never returned through any API (Phase 4 constraint)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    /** JWT bearer token — used to authenticate subsequent requests. */
    private String token;

    /** Token type — always "Bearer" for JWT. */
    private String tokenType;

    /** The authenticated user's database ID. */
    private Long userId;

    /** The authenticated user's username. */
    private String username;

    /** The authenticated user's email address. */
    private String email;

    /** The user's role — USER or ADMIN. */
    private String role;

    /** Human-readable message describing the outcome. */
    private String message;
}
