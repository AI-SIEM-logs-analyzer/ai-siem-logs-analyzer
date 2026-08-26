package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Account rules owned by {@link UserService}. */
@QuarkusTest
class UserServiceTest {

    private static final String PASSWORD = "a-sufficiently-long-password";

    @Inject UserService service;
    @Inject PasswordService passwords;

    @Test
    @TestTransaction
    void storesOnlyAHashOfTheGivenPassword() {
        User created = service.create("hashed", null, PASSWORD, Set.of(Role.ANALYST));

        assertFalse(created.getPasswordHash().contains(PASSWORD));
        assertTrue(passwords.verify(PASSWORD, created.getPasswordHash()));
    }

    @Test
    @TestTransaction
    void rejectsADuplicateUsername() {
        service.create("taken", null, PASSWORD, Set.of(Role.VIEWER));

        DuplicateUserException thrown =
                assertThrows(
                        DuplicateUserException.class,
                        () -> service.create("taken", null, PASSWORD, Set.of(Role.VIEWER)));
        assertEquals("username", thrown.getField());
    }

    @Test
    @TestTransaction
    void rejectsADuplicateEmail() {
        service.create("first", "shared@example.test", PASSWORD, Set.of(Role.VIEWER));

        DuplicateUserException thrown =
                assertThrows(
                        DuplicateUserException.class,
                        () ->
                                service.create(
                                        "second",
                                        "shared@example.test",
                                        PASSWORD,
                                        Set.of(Role.VIEWER)));
        assertEquals("email", thrown.getField());
    }

    @Test
    @TestTransaction
    void keepsAnAccountsOwnEmailOnUpdate() {
        User created =
                service.create("keeps.email", "own@example.test", PASSWORD, Set.of(Role.VIEWER));

        // Writing the same address back is not a collision with itself.
        User updated =
                service.update(created.getId(), "own@example.test", Set.of(Role.ANALYST), true)
                        .orElseThrow();

        assertEquals("own@example.test", updated.getEmail());
        assertEquals(Set.of(Role.ANALYST), updated.getRoles());
    }

    @Test
    @TestTransaction
    void changesAPasswordAndInvalidatesTheOldOne() {
        User created = service.create("rotates", null, PASSWORD, Set.of(Role.ANALYST));

        assertTrue(service.changePassword(created.getId(), "an-entirely-new-password"));

        assertTrue(service.authenticate("rotates", "an-entirely-new-password").isPresent());
        assertTrue(service.authenticate("rotates", PASSWORD).isEmpty());
    }

    @Test
    @TestTransaction
    void authenticatesOnlyEnabledAccountsWithTheRightPassword() {
        service.create("active", null, PASSWORD, Set.of(Role.ANALYST));

        assertTrue(service.authenticate("active", PASSWORD).isPresent());
        assertTrue(service.authenticate("active", "wrong-password-entirely").isEmpty());
        assertTrue(service.authenticate("no-such-user", PASSWORD).isEmpty());

        User created = service.findByUsername("active").orElseThrow();
        service.update(created.getId(), null, Set.of(Role.ANALYST), false);

        assertTrue(service.authenticate("active", PASSWORD).isEmpty());
    }

    @Test
    @TestTransaction
    void refusesToSignInAsTheSeededAdministrator() {
        // The seeded row carries the locked marker, so no password matches it until one is set.
        assertTrue(service.authenticate("admin", "admin").isEmpty());
        assertTrue(service.authenticate("admin", "!").isEmpty());

        User admin = service.findByUsername("admin").orElseThrow();
        service.changePassword(admin.getId(), "the-real-admin-password");

        assertTrue(service.authenticate("admin", "the-real-admin-password").isPresent());
    }

    @Test
    @TestTransaction
    void reportsMissingAccounts() {
        assertEquals(Optional.empty(), service.findById(-1L));
        assertFalse(service.changePassword(-1L, PASSWORD));
        assertFalse(service.delete(-1L));
        assertTrue(service.update(-1L, null, Set.of(Role.VIEWER), true).isEmpty());
    }

    @Test
    @TestTransaction
    void deletesAnAccountWithItsRoles() {
        User created = service.create("temporary", null, PASSWORD, Set.of(Role.ADMIN, Role.VIEWER));

        assertTrue(service.delete(created.getId()));
        assertTrue(service.findByUsername("temporary").isEmpty());
    }
}
