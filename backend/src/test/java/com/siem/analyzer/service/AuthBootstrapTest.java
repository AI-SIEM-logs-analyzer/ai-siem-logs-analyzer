package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The one-off that makes a fresh deployment signable into. */
@QuarkusTest
class AuthBootstrapTest {

    private static final String CHOSEN = "a-chosen-bootstrap-password";

    @Inject AuthBootstrap bootstrap;
    @Inject UserService users;
    @Inject PasswordService passwords;

    @Test
    @TestTransaction
    void givesALockedAdministratorTheConfiguredPassword() {
        User locked = users.create("boot.locked", null, "placeholder-password", Set.of(Role.ADMIN));
        locked.setPasswordHash(PasswordService.LOCKED_HASH);

        bootstrap.applyTo(locked, CHOSEN);

        assertTrue(passwords.verify(CHOSEN, locked.getPasswordHash()));
    }

    @Test
    @TestTransaction
    void leavesAnAdministratorThatAlreadyHasAPasswordAlone() {
        User existing =
                users.create("boot.existing", null, "an-existing-password", Set.of(Role.ADMIN));
        String before = existing.getPasswordHash();

        bootstrap.applyTo(existing, CHOSEN);

        assertEquals(before, existing.getPasswordHash());
        assertTrue(passwords.verify("an-existing-password", existing.getPasswordHash()));
    }
}
