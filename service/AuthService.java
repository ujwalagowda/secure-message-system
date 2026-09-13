package com.securemsg.service;

import com.securemsg.crypto.RSAService;
import com.securemsg.dto.AuthResponse;
import com.securemsg.dto.LoginRequest;
import com.securemsg.dto.RegisterRequest;
import com.securemsg.exception.DuplicateUserException;
import com.securemsg.exception.InvalidCredentialsException;
import com.securemsg.model.User;
import com.securemsg.repository.UserRepository;
import com.securemsg.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.time.LocalDateTime;

/**
 * AuthService
 *
 * Handles user registration and login business logic.
 *
 * Registration flow:
 *   1. Validate that username is not already taken
 *   2. Validate that email is not already registered
 *   3. Generate an RSA-2048 key pair via RSAService
 *   4. Build a new User entity with defaults (role=USER, enabled=true)
 *      and store the encoded public/private keys
 *   5. Save to the database
 *   6. Generate a JWT token for the new user
 *   7. Return AuthResponse with token + user info
 *      (private key is stored in DB but NEVER returned in any response)
 *
 * Login flow:
 *   1. Look up user by username (falls back to email if not found)
 *   2. Verify the account is enabled
 *   3. Compare the submitted password directly against stored password
 *   4. Generate a JWT token
 *   5. Return AuthResponse with token + user info
 *
 * Password handling note:
 *   Passwords are stored and compared as plaintext.
 *   This is a deliberate simplification for this college project.
 *   Introducing bcrypt or Argon2 would add a second cryptographic
 *   algorithm outside the RSA-only scope of this project.
 *
 * RSA note:
 *   RSA-2048 key pairs are generated here via RSAService.
 *   RSA is the ONLY cryptographic algorithm used in this project.
 *   It is used exclusively for message encryption and decryption.
 */
@Service
@Transactional
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RSAService rsaService;

    public AuthService(UserRepository userRepository,
                       JwtTokenProvider jwtTokenProvider,
                       RSAService rsaService) {
        this.userRepository   = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.rsaService       = rsaService;
    }

    // ─────────────────────────────────────────────────────────
    // REGISTRATION
    // ─────────────────────────────────────────────────────────

    /**
     * Registers a new user account and generates their RSA-2048 key pair.
     *
     * RSA key generation happens here:
     *   KeyPairGenerator.getInstance("RSA")  →  2048-bit key pair
     *   publicKey  → Base64 encoded → stored in users.public_key
     *   privateKey → Base64 encoded → stored in users.private_key
     *
     * The private key is stored in the database but is NEVER returned
     * in the AuthResponse or any other API response.
     *
     * @param request validated RegisterRequest DTO from the controller
     * @return AuthResponse containing JWT token and user details (no private key)
     * @throws DuplicateUserException if username or email is already taken
     */
    public AuthResponse register(RegisterRequest request) {

        // 1. Check username uniqueness
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new DuplicateUserException(
                "Username '" + request.getUsername() + "' is already taken."
            );
        }

        // 2. Check email uniqueness
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException(
                "Email '" + request.getEmail() + "' is already registered."
            );
        }

        // 3. Generate RSA-2048 key pair for this user
        //    This is the core RSA operation for this project.
        //    Each user gets a unique key pair used exclusively for
        //    encrypting and decrypting messages sent to/from them.
        KeyPair keyPair = rsaService.generateKeyPair();
        String encodedPublicKey  = rsaService.encodePublicKey(keyPair.getPublic());
        String encodedPrivateKey = rsaService.encodePrivateKey(keyPair.getPrivate());
        // Do NOT log the encoded keys

        logger.info("RSA-2048 key pair generated for new user: '{}'", request.getUsername());

        // 4. Build the User entity
        //    - role defaults to USER (client cannot choose their own role)
        //    - enabled defaults to true
        //    - password stored as plaintext (college project scope)
        //    - publicKey and privateKey stored as Base64 strings
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(request.getPassword())
                .role(User.Role.USER)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .publicKey(encodedPublicKey)
                .privateKey(encodedPrivateKey)   // stored in DB only — never returned via API
                .build();

        // 5. Persist to database
        User savedUser = userRepository.save(user);
        logger.info("New user registered: username='{}', id={}",
                savedUser.getUsername(), savedUser.getId());

        // 6. Generate JWT token for immediate login after registration
        String token = jwtTokenProvider.generateToken(
                savedUser.getUsername(),
                savedUser.getRole().name()
        );

        // 7. Build and return the response
        //    NOTE: privateKey is deliberately excluded from AuthResponse.
        //    The response includes publicKey so the client knows it was generated.
        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .userId(savedUser.getId())
                .username(savedUser.getUsername())
                .email(savedUser.getEmail())
                .role(savedUser.getRole().name())
                .message("Registration successful. RSA-2048 key pair generated. Welcome, "
                         + savedUser.getUsername() + "!")
                .build();
    }

    // ─────────────────────────────────────────────────────────
    // LOGIN
    // ─────────────────────────────────────────────────────────

    /**
     * Authenticates a user and returns a JWT token.
     *
     * Accepts either username or email in the usernameOrEmail field.
     * The error message is intentionally generic to prevent username
     * enumeration (an attacker should not be able to determine whether
     * an account exists by observing the error message).
     *
     * @param request validated LoginRequest DTO from the controller
     * @return AuthResponse containing JWT token and user details
     * @throws InvalidCredentialsException if credentials are wrong or account is disabled
     */
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {

        // 1. Look up user by username, fall back to email
        User user = userRepository
                .findByUsername(request.getUsernameOrEmail())
                .or(() -> userRepository.findByEmail(request.getUsernameOrEmail()))
                .orElseThrow(() ->
                    new InvalidCredentialsException("Invalid username/email or password.")
                );

        // 2. Check account is enabled
        if (!user.isEnabled()) {
            throw new InvalidCredentialsException(
                "This account has been disabled. Please contact the administrator."
            );
        }

        // 3. Compare password directly (plaintext — college project scope)
        if (!request.getPassword().equals(user.getPassword())) {
            throw new InvalidCredentialsException("Invalid username/email or password.");
        }

        logger.info("User logged in: username='{}', id={}",
                user.getUsername(), user.getId());

        // 4. Generate JWT token
        String token = jwtTokenProvider.generateToken(
                user.getUsername(),
                user.getRole().name()
        );

        // 5. Return response (no password, no private key)
        return AuthResponse.builder()
                .token(token)
                .tokenType("Bearer")
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .message("Login successful. Welcome back, " + user.getUsername() + "!")
                .build();
    }
}
