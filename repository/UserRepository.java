package com.securemsg.repository;

import com.securemsg.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * UserRepository
 *
 * Spring Data JPA repository for the User entity.
 * Extends JpaRepository which provides standard CRUD operations:
 *   save(), findById(), findAll(), deleteById(), count(), etc.
 *
 * Custom query methods are declared below using Spring Data's
 * method-name derivation — no SQL or JPQL required.
 *
 * Used by: UserService, AuthService (via UserService)
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find a user by their username.
     * Used during login to locate the account.
     *
     * @param username the username to search for
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByUsername(String username);

    /**
     * Find a user by their email address.
     * Used during login (users may log in with email instead of username)
     * and during registration to prevent duplicate emails.
     *
     * @param email the email address to search for
     * @return Optional containing the User if found, empty otherwise
     */
    Optional<User> findByEmail(String email);

    /**
     * Check whether a username is already taken.
     * Used during registration to prevent duplicate usernames.
     *
     * @param username the username to check
     * @return true if a user with this username already exists
     */
    boolean existsByUsername(String username);

    /**
     * Check whether an email is already registered.
     * Used during registration to prevent duplicate email addresses.
     *
     * @param email the email to check
     * @return true if a user with this email already exists
     */
    boolean existsByEmail(String email);
}
