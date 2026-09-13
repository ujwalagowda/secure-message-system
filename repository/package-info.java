/**
 * repository package
 *
 * Contains Spring Data JPA repository interfaces for database access:
 *   - UserRepository.java       CRUD + custom queries for the users table
 *   - MessageRepository.java    CRUD + queries for sent/received messages
 *
 * Repositories extend JpaRepository and are injected into service classes.
 * These interfaces will be implemented in Phase 3.
 */
package com.securemsg.repository;
