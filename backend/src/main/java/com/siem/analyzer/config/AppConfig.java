package com.siem.analyzer.config;

import com.siem.analyzer.parse.JsonFieldMapping;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.List;
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

    @Valid
    Upload upload();

    @Valid
    Parse parse();

    @Valid
    Search search();

    /** GeoIP enrichment settings. */
    @Valid
    Geoip geoip();

    /** User-Agent classification settings. */
    @Valid
    UserAgent userAgent();

    /** Settings for the line parsers in {@code com.siem.analyzer.parse}. */
    interface Parse {

        @Valid
        Json json();

        /** Settings for {@link com.siem.analyzer.parse.JsonLogParser}. */
        interface Json {

            @Valid
            Fields fields();

            /**
             * Candidate JSON paths for each standard event field, tried in order; the first that
             * holds a usable value wins. Paths are dot-separated and match nested objects and flat
             * dotted keys alike, see {@link com.siem.analyzer.parse.JsonFieldMapping}.
             *
             * <p>Overriding a field replaces its whole list, it does not extend it: set {@code
             * APP_PARSE_JSON_FIELDS_SRC_IP=actor.addr} and {@code source.ip} is no longer read. The
             * defaults are the constants on {@code JsonFieldMapping}, so the parser's unit tests
             * run against exactly what is deployed.
             */
            interface Fields {

                @WithDefault(JsonFieldMapping.DEFAULT_TIMESTAMP)
                List<String> timestamp();

                @WithDefault(JsonFieldMapping.DEFAULT_HOST)
                List<String> host();

                @WithDefault(JsonFieldMapping.DEFAULT_SRC_IP)
                List<String> srcIp();

                @WithDefault(JsonFieldMapping.DEFAULT_SRC_PORT)
                List<String> srcPort();

                @WithDefault(JsonFieldMapping.DEFAULT_USER)
                List<String> user();

                @WithDefault(JsonFieldMapping.DEFAULT_METHOD)
                List<String> method();

                @WithDefault(JsonFieldMapping.DEFAULT_PATH)
                List<String> path();

                @WithDefault(JsonFieldMapping.DEFAULT_PROTOCOL)
                List<String> protocol();

                @WithDefault(JsonFieldMapping.DEFAULT_STATUS)
                List<String> status();

                @WithDefault(JsonFieldMapping.DEFAULT_BYTES)
                List<String> bytes();

                @WithDefault(JsonFieldMapping.DEFAULT_REFERRER)
                List<String> referrer();

                @WithDefault(JsonFieldMapping.DEFAULT_USER_AGENT)
                List<String> userAgent();

                @WithDefault(JsonFieldMapping.DEFAULT_SEVERITY)
                List<String> severity();

                @WithDefault(JsonFieldMapping.DEFAULT_MESSAGE)
                List<String> message();
            }
        }
    }

    /** Settings for the derived OpenSearch index in {@code com.siem.analyzer.search}. */
    interface Search {

        /**
         * The concrete index documents are written to.
         *
         * <p>Versioned on purpose. A mapping change builds the next index and repoints {@link
         * #alias()} at it, so a rebuild needs neither downtime nor a coordinated deploy.
         */
        @WithDefault("log-events-v1")
        @NotBlank
        String indexName();

        /** The name every query and every write uses. Points at {@link #indexName()}. */
        @WithDefault("log-events")
        @NotBlank
        String alias();

        /** Documents per `_bulk` request. */
        @WithDefault("500")
        @Min(1)
        int bulkSize();

        /** How long a search may take before the engine is told to give up. */
        @WithDefault("PT10S")
        Duration queryTimeout();

        @Valid
        Backfill backfill();

        /**
         * The scheduled drain of events PostgreSQL holds and the index does not.
         *
         * <p>This is the path that guarantees an event is eventually searchable. The after-commit
         * hook in {@code EventIndexer} only makes it faster.
         */
        interface Backfill {

            @WithDefault("true")
            boolean enabled();

            @WithDefault("PT30S")
            Duration interval();

            /** Events read from PostgreSQL per run. */
            @WithDefault("1000")
            @Min(1)
            int batchSize();
        }
    }

    /**
     * MaxMind GeoLite2 enrichment. Disabled deployments still start; events simply carry no geo
     * data.
     */
    interface Geoip {

        /** Whether events are enriched at all. */
        @WithDefault("true")
        boolean enabled();

        /** Absolute path of the GeoLite2 City database inside the container. */
        @WithDefault("/opt/geoip/GeoLite2-City.mmdb")
        String cityDatabasePath();

        /** Absolute path of the GeoLite2 ASN database inside the container. */
        @WithDefault("/opt/geoip/GeoLite2-ASN.mmdb")
        String asnDatabasePath();

        /**
         * Networks that are never looked up. A lookup on private, loopback or link-local space
         * returns nothing useful, so it is skipped before it reaches the database.
         */
        @WithDefault(
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7")
        List<String> skippedNetworks();
    }

    /**
     * Yauaa User-Agent classification. Disabled deployments still start; events simply carry no
     * browser, operating system or bot fields.
     */
    interface UserAgent {

        /** Whether events are classified at all. */
        @WithDefault("true")
        boolean enabled();

        /**
         * How many distinct headers keep their classification in memory. Traffic repeats a small
         * set of headers, so a hit here skips the rule engine entirely.
         */
        @WithDefault("10000")
        @Min(0)
        int cacheSize();
    }

    /** Settings for log file upload storage. */
    interface Storage {

        /** Directory where uploaded log files are stored. */
        @WithDefault("data/uploads")
        String uploadDir();
    }

    /**
     * Limits applied to an uploaded log file before it is stored.
     *
     * <p>Everything here is a rejection rule, so every value is deliberately conservative: raising
     * a limit is a decision someone makes per deployment, and the default should not be the one
     * that lets a 2 GiB core dump through.
     */
    interface Upload {

        /**
         * Largest file the application accepts, in bytes.
         *
         * <p>{@code quarkus.http.limits.max-body-size} is set above this on purpose. The HTTP limit
         * exists so a runaway body is cut off before it fills the disk; this one exists so an
         * upload that is merely too large gets a 413 that names the limit.
         */
        @WithDefault("52428800")
        @Min(1)
        long maxFileSizeBytes();

        /**
         * File name extensions accepted, without the leading dot and compared case-insensitively.
         *
         * <p>No compressed formats: ingestion reads the stored file as text and does not
         * decompress, so accepting {@code .gz} would store batches nothing downstream can parse.
         */
        @WithDefault("log,txt,json,ndjson,csv")
        List<String> allowedExtensions();

        /**
         * Multipart content types accepted, parameters stripped and compared case-insensitively.
         *
         * <p>{@code application/octet-stream} is in the list because curl and most HTTP clients
         * send it for any file they cannot type, and refusing it would reject legitimate uploads.
         * That makes this check a cheap filter rather than a barrier — the sniff of the leading
         * bytes is what actually rejects a binary.
         */
        @WithDefault("text/plain,application/json,text/csv,application/octet-stream")
        List<String> allowedContentTypes();

        /** How many leading bytes are read to decide whether the content is text. */
        @WithDefault("8192")
        @Min(1)
        int sniffBytes();

        @Valid
        RateLimit rateLimit();

        /** How many uploads one account may make before being turned away. */
        interface RateLimit {

            @WithDefault("20")
            @Min(1)
            int requests();

            @WithDefault("PT1M")
            Duration window();
        }
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
