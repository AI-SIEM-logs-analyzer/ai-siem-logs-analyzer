package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/** Hashing and verification behaviour of {@link PasswordService}. */
@QuarkusTest
class PasswordServiceTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Inject PasswordService service;

    @Test
    void producesAnArgon2idEncoding() {
        String hash = service.hash(PASSWORD);

        assertTrue(hash.startsWith("$argon2id$"), hash);
        // The plaintext must not be recoverable from, or visible in, what is stored.
        assertFalse(hash.contains(PASSWORD));
        assertNotEquals(PASSWORD, hash);
    }

    @Test
    void saltsEveryHashSeparately() {
        // Two hashes of the same password must differ, otherwise stored hashes could be
        // compared to find accounts that share a password.
        assertNotEquals(service.hash(PASSWORD), service.hash(PASSWORD));
    }

    @Test
    void verifiesTheOriginalPasswordAndNothingElse() {
        String hash = service.hash(PASSWORD);

        assertTrue(service.verify(PASSWORD, hash));
        assertFalse(service.verify("correct horse battery stapl", hash));
        assertFalse(service.verify(PASSWORD.toUpperCase(), hash));
        assertFalse(service.verify("", hash));
        assertFalse(service.verify(null, hash));
    }

    @Test
    void rejectsEveryPasswordAgainstALockedAccount() {
        assertTrue(service.isLocked(PasswordService.LOCKED_HASH));
        assertFalse(service.verify(PASSWORD, PasswordService.LOCKED_HASH));
        assertFalse(service.verify("!", PasswordService.LOCKED_HASH));
    }

    @Test
    void rejectsAStoredValueThatIsNotAHash() {
        // A row holding a plaintext password, or nothing at all, must fail closed rather than
        // throw out of the verification path.
        assertFalse(service.verify(PASSWORD, PASSWORD));
        assertFalse(service.verify(PASSWORD, null));
        assertTrue(service.isLocked(null));
    }

    @Test
    void verifiesAHashWrittenUnderDifferentCostParameters() {
        // Parameters are read back from the encoding, so raising the configured cost must not
        // invalidate credentials stored under the old settings. This hash was produced with
        // m=1024,t=3,p=1 — none of which match the test profile's configuration.
        String foreignHash =
                "$argon2id$v=19$m=1024,t=3,p=1$4RJ40CKt/G00bR0v9K6NxQ"
                        + "$VlEiFoEzHRxuHNPNELOZmFh37NqQNUnrXAW2iT/9PpI";

        assertTrue(service.verify("configuration-independent", foreignHash));
    }

    @Test
    void refusesToHashAnEmptyPassword() {
        assertThrows(IllegalArgumentException.class, () -> service.hash(""));
        assertThrows(IllegalArgumentException.class, () -> service.hash(null));
    }
}
