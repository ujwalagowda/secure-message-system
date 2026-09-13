package com.securemsg.repository;

import com.securemsg.model.ImageMessage;
import com.securemsg.model.ImageMessage.ImageMessageStatus;
import com.securemsg.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * ImageMessageRepository
 *
 * Spring Data JPA repository for the ImageMessage entity.
 * Mirrors the ownership-check pattern used in MessageRepository.
 *
 * All queries enforce sender/recipient ownership so no user can
 * access an image message they are not part of.
 */
@Repository
public interface ImageMessageRepository extends JpaRepository<ImageMessage, Long> {

    /**
     * All image messages received by a user, newest first.
     * Used by GET /api/images/inbox
     */
    List<ImageMessage> findByRecipientOrderBySentAtDesc(User recipient);

    /**
     * All image messages sent by a user, newest first.
     * Used by GET /api/images/sent
     */
    List<ImageMessage> findBySenderOrderBySentAtDesc(User sender);

    /**
     * Find a single image message by ID only if the requesting user
     * is the sender OR the recipient.
     * Prevents ID-guessing attacks — same pattern as MessageRepository.
     */
    @Query("SELECT m FROM ImageMessage m " +
           "WHERE m.id = :id " +
           "AND (m.sender = :user OR m.recipient = :user)")
    Optional<ImageMessage> findByIdAndSenderOrRecipient(
            @Param("id") Long id,
            @Param("user") User user
    );

    /**
     * Count unread image messages (SENT status) for a recipient.
     * Status is passed as a parameter to avoid Hibernate 6 JPQL enum-literal issues.
     */
    @Query("SELECT COUNT(m) FROM ImageMessage m " +
           "WHERE m.recipient = :recipient " +
           "AND m.status = :status")
    long countUnreadByRecipient(
            @Param("recipient") User recipient,
            @Param("status") ImageMessageStatus status
    );
}
