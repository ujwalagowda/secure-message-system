/**
 * service package
 *
 * Contains the business logic layer:
 *   - AuthService.java          User registration, login, JWT issuance
 *   - UserService.java          Fetch users, user profile operations
 *   - MessageService.java       Send (encrypt), receive (list), decrypt messages
 *                               Calls RSAService for all cryptographic operations
 *   - AdminService.java         User enable/disable, stats, message metadata
 *
 * Services are the only layer that interact with repositories and RSAService.
 * Controllers never access repositories or RSAService directly.
 * These classes will be implemented in Phase 3 and beyond.
 */
package com.securemsg.service;
