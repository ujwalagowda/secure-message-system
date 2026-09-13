package com.securemsg.repository;

import com.securemsg.model.Message;
import com.securemsg.model.Message.MessageStatus;
import com.securemsg.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * MessageRepository
 *
 * Spring Data JPA repository for the Message entity.
 * Provides CRUD + custom query methods for inbox, sent, and
 * individual message retrieval.
 *
 * All queries enforce ownership — a user can only retrieve
 * messages where they are the sender or recipient.
 * The actual ownership check before decryption is enforced
 * again at the service layer.
 */
@Repository
public interface MessageRepository extends JpaRepository<Message, Long> {

    /**
     * Returns all messages where the given user is the RECIPIENT,
     * ordered newest first.
     *
     * Used by: GET /api/messages/inbox
     *
     * @param recipient the authenticated user
     * @return list of messages addressed to this user
     */
    List<Message> findByRecipientOrderBySentAtDesc(User recipient);

    /**
     * Returns all messages where the given user is the SENDER,
     * ordered newest first.
     *
     * Used by: GET /api/messages/sent
     *
     * @param sender the authenticated user
     * @return list of messages sent by this user
     */
    List<Message> findBySenderOrderBySentAtDesc(User sender);

    /**
     * Finds a single message by its ID, but only if the requesting user
     * is either the SENDER or the RECIPIENT of that message.
     *
     * This query prevents one user from fetching another user's message
     * by guessing an ID. Both sides of the conversation can view the
     * message metadata, but only the recipient can decrypt it.
     *
     * Used by: GET /api/messages/{id}
     * Used by: GET /api/messages/{id}/decrypt (recipient-only enforced in service)
     *
     * @param id   the message's primary key
     * @param user the authenticated user (checked as sender OR recipient)
     * @return Optional containing the Message if found and accessible
     */
    @Query("SELECT m FROM Message m " +
           "WHERE m.id = :id " +
           "AND (m.sender = :user OR m.recipient = :user)")
    Optional<Message> findByIdAndSenderOrRecipient(
            @Param("id") Long id,
            @Param("user") User user
    );

    /**
     * Counts unread messages (status = SENT) for a recipient.
     * Used for the inbox badge / unread count in the dashboard.
     *
     * The enum value is passed as a named parameter (:status) rather than
     * embedded as a literal in the JPQL string. This is the correct approach
     * for Hibernate 6 / Spring Data JPA — fully-qualified inner enum class
     * paths are not valid JPQL path expressions.
     *
     * Call site (MessageService) passes Message.MessageStatus.SENT as the
     * status argument.
     *
     * @param recipient the authenticated user
     * @param status    the MessageStatus enum value to filter by (pass SENT)
     * @return count of messages matching recipient and status
     */
    @Query("SELECT COUNT(m) FROM Message m " +
           "WHERE m.recipient = :recipient " +
           "AND m.status = :status")
    long countUnreadByRecipient(@Param("recipient") User recipient,
                                @Param("status") MessageStatus status);
}
