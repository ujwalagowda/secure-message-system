package com.securemsg.controller;

import com.securemsg.dto.UserDTO;
import com.securemsg.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * UserController
 *
 * Provides REST endpoints for user information.
 * All endpoints require a valid JWT token.
 *
 * Endpoints:
 *   GET /api/users       — list all users (for Send Message recipient selector)
 *   GET /api/users/me    — current user's own profile
 *   GET /api/users/{id}  — single user's public info
 *
 * Security:
 *   - All responses use UserDTO — privateKey is NEVER included.
 *   - password is NEVER included.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /**
     * GET /api/users
     * Returns all registered users.
     * Used by the frontend Send Message page to populate the recipient dropdown.
     * Returns UserDTO list — no privateKey, no password.
     */
    @GetMapping
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    /**
     * GET /api/users/me
     * Returns the currently authenticated user's own profile.
     * Useful for the frontend to display account information.
     * Returns UserDTO — no privateKey, no password.
     */
    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser(
            @AuthenticationPrincipal UserDetails userDetails) {
        // Find by username from JWT — identity always from token, never from URL
        List<UserDTO> all = userService.getAllUsers();
        return all.stream()
                .filter(u -> u.getUsername().equals(userDetails.getUsername()))
                .findFirst()
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * GET /api/users/{id}
     * Returns a single user's public profile by ID.
     * Returns UserDTO — no privateKey, no password.
     */
    @GetMapping("/{id}")
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {
        return ResponseEntity.ok(userService.getUserDTOById(id));
    }
}
