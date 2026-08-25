package com.siem.analyzer.service;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import com.siem.analyzer.repo.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Account management.
 *
 * <p>Owns the rules the REST layer must not restate: usernames and e-mail addresses are unique, an
 * account always holds at least one role, and a password only ever reaches the database through
 * {@link PasswordService}.
 */
@ApplicationScoped
public class UserService {

    private final UserRepository repository;
    private final PasswordService passwordService;

    @Inject
    public UserService(UserRepository repository, PasswordService passwordService) {
        this.repository = repository;
        this.passwordService = passwordService;
    }

    /** Every account, ordered by username. */
    public List<User> list() {
        return repository.find("order by username").list();
    }

    public Optional<User> findById(Long id) {
        return Optional.ofNullable(repository.findById(id));
    }

    public Optional<User> findByUsername(String username) {
        return repository.findByUsername(username);
    }

    /** Accounts holding the given role. */
    public List<User> listByRole(Role role) {
        return repository.listByRole(role);
    }

    /**
     * Creates an account with an initial password.
     *
     * @throws DuplicateUserException if the username or e-mail address is already taken
     */
    @Transactional
    public User create(String username, String email, String plaintextPassword, Set<Role> roles) {
        requireAvailable(username, email, null);

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPasswordHash(passwordService.hash(plaintextPassword));
        user.setRoles(roles);
        repository.persist(user);
        return user;
    }

    /**
     * Updates the mutable parts of an account: its e-mail address, its roles and whether it can
     * sign in. The username is immutable — it is how the account is referred to in audit trails,
     * and rewriting it would silently detach those from the account they describe.
     *
     * @return empty if no account has that id
     * @throws DuplicateUserException if the e-mail address belongs to another account
     */
    @Transactional
    public Optional<User> update(Long id, String email, Set<Role> roles, boolean enabled) {
        Optional<User> found = findById(id);
        if (found.isEmpty()) {
            return found;
        }

        User user = found.get();
        requireAvailable(null, email, id);
        user.setEmail(email);
        user.setRoles(roles);
        user.setEnabled(enabled);
        return Optional.of(user);
    }

    /**
     * Replaces an account's password.
     *
     * @return false if no account has that id
     */
    @Transactional
    public boolean changePassword(Long id, String plaintextPassword) {
        Optional<User> found = findById(id);
        if (found.isEmpty()) {
            return false;
        }
        found.get().setPasswordHash(passwordService.hash(plaintextPassword));
        return true;
    }

    /**
     * Deletes an account. The roles go with it, through the cascade on {@code fk_user_role_user}.
     *
     * @return false if no account has that id
     */
    @Transactional
    public boolean delete(Long id) {
        return repository.deleteById(id);
    }

    /**
     * Checks a username and password pair.
     *
     * <p>A disabled account fails here rather than at a later authorisation step, and it fails the
     * same way a wrong password does, so a caller cannot tell the two apart. An account whose hash
     * is the locked marker fails too, because {@link PasswordService#verify} rejects every input
     * against it.
     *
     * @return the account when the credentials are valid and it is enabled, empty otherwise
     */
    public Optional<User> authenticate(String username, String plaintextPassword) {
        Optional<User> found = repository.findByUsername(username);
        String storedHash = found.map(User::getPasswordHash).orElse(PasswordService.LOCKED_HASH);

        boolean valid = passwordService.verify(plaintextPassword, storedHash);
        if (!valid) {
            return Optional.empty();
        }
        return found.filter(User::isEnabled);
    }

    /**
     * Fails if the username or e-mail address is taken by an account other than {@code selfId}.
     *
     * @param selfId id of the account being updated, or null when creating one
     */
    private void requireAvailable(String username, String email, Long selfId) {
        if (username != null) {
            Optional<User> byUsername = repository.findByUsername(username);
            if (isOther(byUsername, selfId)) {
                throw new DuplicateUserException("username", username);
            }
        }
        if (email != null && !email.isBlank()) {
            Optional<User> byEmail = repository.find("email", email).firstResultOptional();
            if (isOther(byEmail, selfId)) {
                throw new DuplicateUserException("email", email);
            }
        }
    }

    /** Whether the match is an account other than the one being written. */
    private static boolean isOther(Optional<User> match, Long selfId) {
        return match.isPresent() && !match.get().getId().equals(selfId);
    }
}
