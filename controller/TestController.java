package com.securemsg.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * TestController
 *
 * A simple health-check controller to verify that the Spring Boot
 * application starts correctly and the REST layer is reachable.
 *
 * Endpoint:
 *   GET /api/test
 *
 * This controller will be removed or replaced once the full
 * AuthController and MessageController are in place (Phase 3+).
 */
@RestController
@RequestMapping("/api")
public class TestController {

    /**
     * GET /api/test
     *
     * Returns a JSON response confirming the backend is running.
     * This endpoint is publicly accessible (no authentication required)
     * so it can be used as a startup health check.
     *
     * Sample response:
     * {
     *   "status"      : "OK",
     *   "message"     : "Secure Message System Backend Running",
     *   "algorithm"   : "RSA-2048",
     *   "description" : "Secure Message Communication System Using RSA Cryptographic Algorithm",
     *   "timestamp"   : "2026-09-11T14:32:05.123"   <-- actual current server time, dynamic
     * }
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, Object>> test() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "OK");
        response.put("message", "Secure Message System Backend Running");
        response.put("algorithm", "RSA-2048");
        response.put("description", "Secure Message Communication System Using RSA Cryptographic Algorithm");
        response.put("timestamp", LocalDateTime.now().toString());
        return ResponseEntity.ok(response);
    }
}
