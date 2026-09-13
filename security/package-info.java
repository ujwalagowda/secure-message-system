/**
 * security package
 *
 * Contains Spring Security and JWT infrastructure classes.
 *
 *   - JwtTokenProvider.java           Creates and validates JWT tokens
 *                                     using a plain server-side secret string.
 *                                     NOT a cryptographic algorithm — just HMAC
 *                                     via the JJWT library for session management.
 *
 *   - JwtAuthenticationFilter.java    OncePerRequestFilter that extracts the JWT
 *                                     from the Authorization header, validates it,
 *                                     and sets the SecurityContext for each request.
 *
 *   - UserDetailsServiceImpl.java     Implements Spring Security's UserDetailsService.
 *                                     Loads a user from the database by username
 *                                     so Spring Security can verify credentials.
 *
 * NOTE: JWT signing here is for session authentication only.
 * RSA is NOT used here. RSA is used exclusively in the crypto package
 * for message encryption/decryption.
 *
 * These classes will be implemented in Phase 3.
 */
package com.securemsg.security;
