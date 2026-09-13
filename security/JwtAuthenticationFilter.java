package com.securemsg.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter
 *
 * A Spring Security filter that runs exactly once per HTTP request.
 * It intercepts every incoming request and:
 *
 *   1. Extracts the JWT from the Authorization header
 *      (format: "Authorization: Bearer <token>")
 *
 *   2. Validates the token using JwtTokenProvider.
 *
 *   3. If valid, loads the user from the database via
 *      UserDetailsServiceImpl and sets the authentication
 *      in the Spring SecurityContext.
 *
 *   4. If invalid or absent, does nothing — the request
 *      continues and Spring Security will reject it at the
 *      route authorization level if the endpoint is protected.
 *
 * Extends OncePerRequestFilter to guarantee single execution
 * per request even in filter chains that invoke it multiple times.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtTokenProvider jwtTokenProvider;
    private final UserDetailsServiceImpl userDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider,
                                   UserDetailsServiceImpl userDetailsService) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Core filter logic executed for every incoming HTTP request.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // Step 1: Extract JWT from the Authorization header
            String token = extractTokenFromRequest(request);

            // Step 2: Validate the token
            if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {

                // Step 3: Extract username from token
                String username = jwtTokenProvider.getUsernameFromToken(token);

                // Step 4: Load user details from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Step 5: Build authentication object and set it in SecurityContext
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,                          // credentials not needed after auth
                                userDetails.getAuthorities()
                        );
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            // Log the error but do NOT expose details to the client
            logger.error("Could not set user authentication in security context: {}", e.getMessage());
            // Clear any partial auth state
            SecurityContextHolder.clearContext();
        }

        // Always continue the filter chain regardless of auth outcome
        filterChain.doFilter(request, response);
    }

    /**
     * Extracts the JWT bearer token from the Authorization request header.
     *
     * Expected header format:
     *   Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
     *
     * @param request the incoming HTTP request
     * @return the token string if present and well-formed, null otherwise
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove "Bearer " prefix (7 characters)
        }
        return null;
    }
}
