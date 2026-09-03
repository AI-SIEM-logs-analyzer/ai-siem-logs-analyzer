package com.siem.analyzer.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.Optional;

/**
 * Application-owned configuration, rooted at the {@code app} prefix in application.yaml.
 *
 * <p>Everything here is resolved and validated while the application boots, so a missing or
 * malformed value fails the start-up rather than the first request that needs it. Values come from
 * application.yaml, from a local {@code .env} file in dev mode, or from environment variables, in
 * increasing order of precedence.
 */
@ConfigMapping(prefix = "app")
public interface AppConfig {

    /**
     * Name of the environment the application runs in, e.g. {@code dev}, {@code test}, {@code
     * prod}.
     */
    @NotBlank
    String environment();

    @Valid
    Ai ai();

    @Valid
    Security security();

    @Valid
    Auth auth();

    @Valid
    Storage storage();

    /** Settings for log file upload storage. */
    interface Storage {

        /** Directory where uploaded log files are stored. */
        @WithDefault("data/uploads")
        String uploadDir();
    }

    /** Settings for the AI provider used to analyse logs. */
    interface Ai {

        /**
         * API key for the AI provider.
         *
         * <p>Deliberately has no default and no value under the {@code prod} profile: production
         * has to supply {@code APP_AI_API_KEY} through the environment, and the application refuses
         * to start without it. Dev and test carry a placeholder so neither the dev loop nor CI
         * depends on a real secret.
         */
        @NotBlank
        String apiKey();
    }

    /** Settings that govern how credentials are stored. */
    interface Security {

        @Valid
        Argon2Settings argon2();

        /**
         * Cost parameters for the Argon2id hash applied to passwords.
         *
         * <p>Defaults follow the OWASP recommendation of 19 MiB of memory, two iterations and one
         * degree of parallelism, which is the cheapest of the recommended pairs and the one that
         * suits a request-path hash on a shared server. They are configurable because the right
         * cost depends on the hardware: it should be raised until a single hash takes on the order
         * of half a second on the target machine.
         *
         * <p>Changing any of these leaves stored hashes valid. Verification reads the parameters
         * back from the encoded hash itself, so the new settings apply to passwords set from then
         * on and old rows keep verifying under the settings they were written with.
         */
        interface Argon2Settings {

            /** Memory cost in kibibytes. */
            @WithDefault("19456")
            @Min(8)
            int memoryKib();

            /** Number of passes over memory. */
            @WithDefault("2")
            @Min(1)
            int iterations();

            /** Number of lanes computed in parallel. */
            @WithDefault("1")
            @Min(1)
            int parallelism();

            /** Length of the derived hash, in bytes. */
            @WithDefault("32")
            @Min(16)
            int hashLengthBytes();

            /**
             * Length of the per-password random salt, in bytes.
             *
             * <p>16 is the value RFC 9106 recommends for password hashing; the salt is stored
             * inside the encoded hash, so it costs nothing to keep it there.
             */
            @WithDefault("16")
            @Min(8)
            int saltLengthBytes();
        }
    }

    /** Settings for the tokens this application issues and accepts. */
    interface Auth {

        /**
         * Value of the {@code iss} claim on every access token, and the issuer the verifier
         * demands. Deployment-specific: a token minted for one deployment must not verify against
         * another, and this claim is what separates them.
         */
        @NotBlank
        String issuer();

        /**
         * How long an access token stays valid.
         *
         * <p>Short by design. The token is verified without touching Redis, so apart from an
         * explicit logout this window is how long a change of roles or a disabled account takes to
         * bite.
         */
        @WithDefault("PT15M")
        Duration accessTtl();

        /** How long a refresh token stays valid, and the TTL of everything Redis stores for it. */
        @WithDefault("P14D")
        Duration refreshTtl();

        /**
         * First password for the seeded administrator, whose stored hash is the locked marker until
         * someone sets one. Applied at start-up, once; empty on a deployment whose administrator
         * already has a password.
         */
        Optional<String> bootstrapPassword();

        @Valid
        RateLimit rateLimit();

        /** How many failed sign-ins one username and address may make before being turned away. */
        interface RateLimit {

            @WithDefault("10")
            @Min(1)
            int attempts();

            @WithDefault("PT15M")
            Duration window();
        }
    }
}
