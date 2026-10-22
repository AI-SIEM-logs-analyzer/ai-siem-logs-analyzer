package com.siem.analyzer.service;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import com.siem.analyzer.config.AppConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
public class PasswordService {

    public static final String LOCKED_HASH = "!";

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

    public String hash(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        return Password.hash(plaintext).addRandomSalt(saltLengthBytes).with(function).getResult();
    }

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

    public boolean isLocked(String storedHash) {
        return storedHash == null || !storedHash.startsWith(ARGON2_PREFIX);
    }
}
