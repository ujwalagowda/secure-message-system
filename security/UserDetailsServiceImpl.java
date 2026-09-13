package com.securemsg.security;

import com.securemsg.model.User;
import com.securemsg.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * UserDetailsServiceImpl
 *
 * Implements Spring Security's UserDetailsService interface.
 * Spring Security calls loadUserByUsername() to fetch a user
 * from the database during authentication so it can verify
 * credentials and build the security context.
 *
 * The returned UserDetails object carries:
 *   - username
 *   - password  (used by Spring Security for credential verification)
 *   - authorities (roles, e.g. ROLE_USER or ROLE_ADMIN)
 *   - account status flags (enabled, locked, etc.)
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Loads a user from the database by username.
     * Called by Spring Security's authentication process.
     *
     * The user's role is prefixed with "ROLE_" as required by
     * Spring Security's authority naming convention:
     *   USER  → ROLE_USER
     *   ADMIN → ROLE_ADMIN
     *
     * @param username the username to look up
     * @return UserDetails containing credentials and authorities
     * @throws UsernameNotFoundException if no user exists with this username
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                    new UsernameNotFoundException("User not found with username: " + username)
                );

        // Build Spring Security authority from the user's role
        // Convention: ROLE_ prefix is required by Spring Security
        String authority = "ROLE_" + user.getRole().name();

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities(new SimpleGrantedAuthority(authority))
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!user.isEnabled())
                .build();
    }
}
