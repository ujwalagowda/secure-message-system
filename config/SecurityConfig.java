package com.securemsg.config;

import com.securemsg.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig — Phase 3 (full JWT authentication version)
 *
 * Configures Spring Security for this stateless REST API:
 *
 * Public routes (no JWT required):
 *   POST /api/auth/register   — user registration
 *   POST /api/auth/login      — user login
 *   GET  /api/test            — health check
 *
 * Protected routes (valid JWT required):
 *   /api/users/**             — USER or ADMIN role
 *   /api/messages/**          — USER or ADMIN role
 *   /api/admin/**             — ADMIN role only
 *
 * Security design:
 *   - CSRF disabled — not needed for stateless JWT-based REST APIs
 *   - Sessions STATELESS — no HttpSession; identity carried in JWT only
 *   - JwtAuthenticationFilter runs before Spring's default auth filter
 *   - PasswordEncoder set to NoOpPasswordEncoder (plaintext comparison)
 *     because this project stores passwords as plaintext to avoid
 *     introducing a second cryptographic algorithm (bcrypt/Argon2)
 *     outside the RSA-only scope.
 *
 * @EnableMethodSecurity enables @PreAuthorize annotations on controller
 * methods for fine-grained method-level security in later phases.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    // ─────────────────────────────────────────────────────────
    // Security Filter Chain — main HTTP security rules
    // ─────────────────────────────────────────────────────────

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 1. Disable CSRF — stateless REST API with JWT does not need it
            .csrf(AbstractHttpConfigurer::disable)

            // 2. Stateless sessions — JWT carries identity, no server-side session
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // 3. Route-level authorization rules
            .authorizeHttpRequests(auth -> auth

                // ── Public endpoints (no token needed) ──────────────────
                .requestMatchers(
                    "/api/auth/register",
                    "/api/auth/login",
                    "/api/test"
                ).permitAll()

                // ── Admin-only endpoints ─────────────────────────────────
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // ── All other /api/** endpoints require authentication ───
                // Role (USER or ADMIN) is verified at service/method level
                .requestMatchers("/api/**").authenticated()

                // ── Everything else (non-API) — deny by default ──────────
                .anyRequest().denyAll()
            )

            // 4. Register the JWT filter before Spring's default auth filter
            //    This ensures every request is checked for a valid JWT token
            //    before Spring Security's own authentication mechanism runs
            .addFilterBefore(jwtAuthenticationFilter,
                             UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ─────────────────────────────────────────────────────────
    // PasswordEncoder
    //
    // NoOpPasswordEncoder performs a plain String.equals() comparison.
    // This is intentional — passwords are stored as plaintext in this
    // college project to avoid introducing bcrypt or Argon2, which are
    // cryptographic algorithms outside the RSA-only project scope.
    //
    // Spring Security requires a PasswordEncoder bean to be present even
    // when not hashing, so this explicit bean satisfies that requirement.
    // ─────────────────────────────────────────────────────────

    @Bean
    @SuppressWarnings("deprecation")
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    // ─────────────────────────────────────────────────────────
    // AuthenticationManager
    //
    // Exposes Spring's AuthenticationManager as a bean.
    // Required if any service or controller needs to programmatically
    // trigger authentication (e.g. during login via Spring's auth chain).
    // ─────────────────────────────────────────────────────────

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
