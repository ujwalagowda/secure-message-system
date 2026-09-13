package com.securemsg.service;

import com.securemsg.dto.UserDTO;
import com.securemsg.exception.UserNotFoundException;
import com.securemsg.model.User;
import com.securemsg.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * UserService
 *
 * Handles user-related operations:
 *   - Listing all registered users     (for the Send Message recipient selector)
 *   - Fetching a single user by ID     (for message metadata)
 *   - Resolving the current user by username (internal use by other services)
 *
 * Security: all public-facing methods return UserDTO, which explicitly
 * excludes the privateKey field. The privateKey is accessible only via
 * getUserById() (internal) which returns the full User entity, and is
 * used solely by MessageService for RSA decryption.
 */
@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Returns all registered users as UserDTOs.
     * Used by UserController → GET /api/users.
     * Used by the frontend Send Message page to populate the recipient selector.
     *
     * privateKey is NEVER included in UserDTO.
     */
    @Transactional(readOnly = true)
    public List<UserDTO> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(UserDTO::from)
                .collect(Collectors.toList());
    }

    /**
     * Returns a single user as UserDTO by ID.
     * Used by UserController → GET /api/users/{id}.
     *
     * @throws UserNotFoundException if no user exists with this ID
     */
    @Transactional(readOnly = true)
    public UserDTO getUserDTOById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
        return UserDTO.from(user);
    }

    /**
     * Returns the full User entity by username.
     * INTERNAL USE ONLY — called by MessageService and AuthService.
     * Never pass the returned entity directly to a controller response.
     *
     * @throws UserNotFoundException if no user exists with this username
     */
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(
                    "User not found with username: " + username));
    }

    /**
     * Returns the full User entity by ID.
     * INTERNAL USE ONLY — called by MessageService.
     *
     * @throws UserNotFoundException if no user exists with this ID
     */
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));
    }
}
