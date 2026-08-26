package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.PersistenceException;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Persistence behaviour of {@link User}, exercised against the real schema. */
@QuarkusTest
class UserRepositoryTest {

    // Not a credential: the column only ever holds an encoded hash, and nothing in these
    // tests verifies a password. It has to satisfy ck_app_user_password_hash all the same.
    private static final String HASH = "$argon2id$v=19$m=512,t=1,p=1$c2FsdHNhbHRzYWx0$ZGlnZXN0";

    @Inject UserRepository repository;

    private static User user(String username, Role... roles) {
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(HASH);
        user.setRoles(Set.of(roles));
        return user;
    }

    @Test
    @TestTransaction
    void persistsAndReadsBackAllFields() {
        User stored = user("nadia.analyst", Role.ANALYST);
        stored.setEmail("nadia@example.test");

        repository.persist(stored);
        repository.flush();

        User found = repository.findById(stored.getId());
        assertNotNull(found.getId());
        assertEquals("nadia.analyst", found.getUsername());
        assertEquals("nadia@example.test", found.getEmail());
        assertEquals(HASH, found.getPasswordHash());
        assertTrue(found.isEnabled());
        assertNotNull(found.getCreatedAt());
        assertNotNull(found.getUpdatedAt());
    }

    @Test
    @TestTransaction
    void storesSeveralRolesForOneAccount() {
        User stored = user("multi.role", Role.ADMIN, Role.ANALYST);

        repository.persist(stored);
        repository.flush();

        User found = repository.findById(stored.getId());
        assertEquals(EnumSet.of(Role.ADMIN, Role.ANALYST), EnumSet.copyOf(found.getRoles()));
        assertTrue(found.hasRole(Role.ADMIN));
        assertFalse(found.hasRole(Role.VIEWER));
    }

    @Test
    @TestTransaction
    void replacesTheRoleSetOnUpdate() {
        User stored = user("demoted", Role.ADMIN);
        repository.persist(stored);
        repository.flush();

        stored.setRoles(Set.of(Role.VIEWER));
        repository.flush();
        repository.getEntityManager().clear();

        assertEquals(Set.of(Role.VIEWER), repository.findById(stored.getId()).getRoles());
    }

    @Test
    @TestTransaction
    void findsByUsername() {
        repository.persist(user("findable", Role.VIEWER));
        repository.flush();

        assertTrue(repository.findByUsername("findable").isPresent());
        assertTrue(repository.findByUsername("does-not-exist").isEmpty());
    }

    @Test
    @TestTransaction
    void listsOnlyEnabledAccounts() {
        User enabled = user("still.here", Role.VIEWER);
        User disabled = user("left.the.company", Role.VIEWER);
        disabled.setEnabled(false);

        repository.persist(enabled);
        repository.persist(disabled);
        repository.flush();

        List<String> usernames = repository.listEnabled().stream().map(User::getUsername).toList();
        assertTrue(usernames.contains("still.here"));
        assertFalse(usernames.contains("left.the.company"));
    }

    @Test
    @TestTransaction
    void listsByRoleWithoutDuplicatingMultiRoleAccounts() {
        repository.persist(user("only.admin", Role.ADMIN));
        repository.persist(user("admin.and.analyst", Role.ADMIN, Role.ANALYST));
        repository.persist(user("plain.viewer", Role.VIEWER));
        repository.flush();

        List<String> admins =
                repository.listByRole(Role.ADMIN).stream().map(User::getUsername).toList();

        // 'admin' is seeded by V2__users.sql, so the listing is asserted by membership rather
        // than by size.
        assertTrue(admins.contains("only.admin"));
        assertTrue(admins.contains("admin.and.analyst"));
        assertFalse(admins.contains("plain.viewer"));
        assertEquals(admins.size(), admins.stream().distinct().count());
    }

    @Test
    @TestTransaction
    void rejectsADuplicateUsername() {
        repository.persist(user("duplicate", Role.VIEWER));
        repository.flush();

        assertThrows(
                PersistenceException.class,
                () -> {
                    repository.persist(user("duplicate", Role.VIEWER));
                    repository.flush();
                });
    }

    @Test
    @TestTransaction
    void rejectsAPasswordHashThatIsNotArgon2() {
        User stored = user("bad.hash", Role.VIEWER);
        stored.setPasswordHash("plaintext-password");

        assertThrows(
                PersistenceException.class,
                () -> {
                    repository.persist(stored);
                    repository.flush();
                });
    }

    @Test
    @TestTransaction
    void seedsALockedAdministrator() {
        User admin = repository.findByUsername("admin").orElseThrow();

        assertTrue(admin.hasRole(Role.ADMIN));
        assertTrue(admin.isEnabled());
        // The seeded row carries the locked marker, not a hash of any password.
        assertEquals("!", admin.getPasswordHash());
    }
}
