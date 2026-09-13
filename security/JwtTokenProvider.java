package com.securemsg.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JwtTokenProvider
 *
 * Responsible for creating and validating JWT tokens used for
 * session authentication in this application.
 *
 * How it works:
 *   1. On login, generateToken() creates a signed JWT containing
 *      the username, role, and expiry time.
 *   2. On every subsequent request, JwtAuthenticationFilter calls
 *      validateToken() to verify the token is genuine and not expired.
 *   3. getUsernameFromToken() extracts the username from a valid token
 *      so Spring Security can load the user from the database.
 *
 * JWT signing:
 *   The token is signed using an HMAC key derived from the plain
 *   server secret string defined in application.properties.
 *   This is standard JWT session management — NOT a cryptographic
 *   algorithm applied to message data.
 *
 * NOTE: RSA is NOT used here. RSA is used exclusively in RSAService
 *       for encrypting and decrypting user messages (Phase 4).
 */
@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    /** Plain server-side secret from application.properties — never logged or exposed. */
    @Value("${jwt.secret}")
    private String jwtSecret;

    /** Token validity in milliseconds (default 86400000 = 24 hours). */
    @Value("${jwt.expiration-ms}")
    private long jwtExpirationMs;

    /**
     * Derives a SecretKey from the configured jwt.secret string.
     * Called internally before every sign/verify operation.
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generates a JWT token for a successfully authenticated user.
     *
     * @param username the authenticated user's username (becomes the JWT subject)
     * @param role     the user's role (USER or ADMIN), stored as a custom claim
     * @return signed JWT string to be returned to the frontend
     */
    public String generateToken(String username, String role) {
        Date now    = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extracts the username (subject) from a valid JWT token.
     *
     * @param token the JWT string from the Authorization header
     * @return the username stored in the token's subject claim
     */
    public String getUsernameFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * Extracts the role claim from a valid JWT token.
     *
     * @param token the JWT string
     * @return the role string (e.g. "USER" or "ADMIN")
     */
    public String getRoleFromToken(String token) {
        return (String) Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role");
    }

    /**
     * Validates a JWT token.
     * Returns true if the token is well-formed, properly signed,
     * and not expired. Returns false for any other case.
     *
     * Errors are logged at WARN level but never thrown to the client
     * to avoid leaking internal details.
     *
     * @param token the JWT string to validate
     * @return true if valid, false otherwise
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token is expired");
        } catch (UnsupportedJwtException e) {
            logger.warn("JWT token is unsupported");
        } catch (MalformedJwtException e) {
            logger.warn("JWT token is malformed");
        } catch (SecurityException e) {
            logger.warn("JWT signature validation failed");
        } catch (IllegalArgumentException e) {
            logger.warn("JWT token is empty or null");
        }
        return false;
    }
}
