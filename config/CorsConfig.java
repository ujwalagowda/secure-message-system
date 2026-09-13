package com.securemsg.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

/**
 * CorsConfig
 *
 * Configures Cross-Origin Resource Sharing (CORS) so that the frontend
 * (HTML/CSS/JS files opened in a browser or served from a local file server)
 * can make API calls to the Spring Boot backend on port 8080.
 *
 * Allowed origins cover the most common local development setups:
 *   - file://        opening HTML files directly from disk
 *   - localhost:5500 Live Server (VS Code extension)
 *   - localhost:3000 any Node-based dev server
 *   - localhost:8080 same origin (direct backend access)
 *
 * In a production deployment this should be restricted to the actual
 * frontend domain only.
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration config = new CorsConfiguration();

        // Allow credentials (Authorization header / cookies)
        config.setAllowCredentials(true);

        // Allowed frontend origins for local development
        config.setAllowedOriginPatterns(List.of(
            "http://localhost:*",
            "http://127.0.0.1:*",
            "null"          // "null" origin is sent when opening HTML files directly from disk
        ));

        // Allowed HTTP methods
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));

        // Allowed request headers
        config.setAllowedHeaders(List.of("*"));

        // Expose the Authorization header to frontend JavaScript
        config.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        return new CorsFilter(source);
    }
}
