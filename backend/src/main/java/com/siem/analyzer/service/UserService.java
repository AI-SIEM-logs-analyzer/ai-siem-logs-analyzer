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

@ApplicationScoped
public class UserService {

    private final UserRepository repository;
    private final PasswordService passwordService;

    @Inject
    public UserService(UserRepository repository, PasswordService passwordService) {
        this.repository = repository;
        this.passwordService = passwordService;
    }

    public List<User> list() {
        return repository.find("order by username").list();
    }

    public Optional<User> findById(Long id) {
        return Optional.ofNullable(repository.findById(id));
    }

    public Optional<User> findByUsername(String username) {
        return repository.findByUsername(username);
    }

    public List<User> listByRole(Role role) {
        return repository.listByRole(role);
    }

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

    @Transactional
    public boolean changePassword(Long id, String plaintextPassword) {
        Optional<User> found = findById(id);
        if (found.isEmpty()) {
            return false;
        }
        found.get().setPasswordHash(passwordService.hash(plaintextPassword));
        return true;
    }

    @Transactional
    public boolean delete(Long id) {
        return repository.deleteById(id);
    }

    public Optional<User> authenticate(String username, String plaintextPassword) {
        Optional<User> found = repository.findByUsername(username);
        String storedHash = found.map(User::getPasswordHash).orElse(PasswordService.LOCKED_HASH);

        boolean valid = passwordService.verify(plaintextPassword, storedHash);
        if (!valid) {
            return Optional.empty();
        }
        return found.filter(User::isEnabled);
    }

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

    private static boolean isOther(Optional<User> match, Long selfId) {
        return match.isPresent() && !match.get().getId().equals(selfId);
    }
}
