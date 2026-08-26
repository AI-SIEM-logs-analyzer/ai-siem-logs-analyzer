package com.siem.analyzer.service;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import com.siem.analyzer.config.AppConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Turns passwords into stored credentials and checks them back.
 *
 * <p>The only place in the application that handles a plaintext password. Everything downstream —
 * the entity, the repository, the API responses — sees the encoded hash and nothing else.
 *
 * <p>Argon2id is the variant used: it is the one RFC 9106 recommends when the attacker's advantage
 * is unknown, because it resists both side-channel and time-memory trade-off attacks, whereas
 * Argon2i and Argon2d each give up one of those.
 */
@ApplicationScoped
public class PasswordService {

    /**
     * Password hash of an account that cannot be signed into.
     *
     * <p>Not a hash of any password: it is not a valid Argon2 encoding, so {@link #verify} rejects
     * every input against it. Used for accounts that exist before a password has been chosen — the
     * bootstrap administrator seeded by {@code V2__users.sql} is the first of them — which is safer
     * than seeding a placeholder password that would be identical on every deployment.
     */
    public static final String LOCKED_HASH = "!";

    /** Prefix of every encoding this service produces, and the marker {@link #verify} demands. */
    private static final String ARGON2_PREFIX = "$argon2";

    private final Argon2Function function;
    private final int saltLengthBytes;

    @Inject
    public PasswordService(AppConfig config) {
        AppConfig.Security.Argon2Settings settings = config.security().argon2();
        this.function =
                Argon2Function.getInstance(
                        settings.memoryKib(),
                        settings.iterations(),
                        settings.parallelism(),
                        settings.hashLengthBytes(),
                        Argon2.ID);
        this.saltLengthBytes = settings.saltLengthBytes();
    }

    /**
     * Hashes a password for storage.
     *
     * <p>Each call draws a fresh random salt, so hashing the same password twice gives two
     * different results and stored hashes cannot be compared to find users who share a password.
     *
     * @return the encoded hash, carrying the algorithm, its parameters, the salt and the digest
     */
    public String hash(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        return Password.hash(plaintext).addRandomSalt(saltLengthBytes).with(function).getResult();
    }

    /**
     * Checks a password against a stored hash.
     *
     * <p>The verification parameters come from the stored hash rather than from configuration, so
     * raising the cost settings does not invalidate credentials written under the old ones.
     *
     * @return false for a null, empty or non-Argon2 stored hash, including {@link #LOCKED_HASH}
     */
    public boolean verify(String plaintext, String storedHash) {
        if (plaintext == null || plaintext.isEmpty()) {
            return false;
        }
        if (storedHash == null || !storedHash.startsWith(ARGON2_PREFIX)) {
            return false;
        }
        return Password.check(plaintext, storedHash)
                .with(Argon2Function.getInstanceFromHash(storedHash));
    }

    /** Whether the given stored hash belongs to an account with no usable password. */
    public boolean isLocked(String storedHash) {
        return storedHash == null || !storedHash.startsWith(ARGON2_PREFIX);
    }
}
