package com.siem.analyzer.config;

import com.siem.analyzer.ai.AiProvider;
import com.siem.analyzer.parse.JsonFieldMapping;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

@ConfigMapping(prefix = "app")
public interface AppConfig {

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

    @Valid
    Geoip geoip();

    @Valid
    UserAgent userAgent();

    @Valid
    Attack attack();

    interface Parse {

        @Valid
        Json json();

        interface Json {

            @Valid
            Fields fields();

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

    interface Search {

        @WithDefault("log-events-v1")
        @NotBlank
        String indexName();

        @WithDefault("log-events")
        @NotBlank
        String alias();

        @WithDefault("500")
        @Min(1)
        int bulkSize();

        @WithDefault("PT10S")
        Duration queryTimeout();

        @Valid
        Backfill backfill();

        interface Backfill {

            @WithDefault("true")
            boolean enabled();

            @WithDefault("PT30S")
            Duration interval();

            @WithDefault("1000")
            @Min(1)
            int batchSize();
        }
    }

    interface Geoip {

        @WithDefault("true")
        boolean enabled();

        @WithDefault("/opt/geoip/GeoLite2-City.mmdb")
        String cityDatabasePath();

        @WithDefault("/opt/geoip/GeoLite2-ASN.mmdb")
        String asnDatabasePath();

        @WithDefault(
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fc00::/7")
        List<String> skippedNetworks();
    }

    interface UserAgent {

        @WithDefault("true")
        boolean enabled();

        @WithDefault("10000")
        @Min(0)
        int cacheSize();
    }

    interface Attack {

        @WithDefault("true")
        boolean importOnStart();

        @WithDefault("mitre/enterprise-attack-19.2.json.gz")
        String bundledResource();

        @WithDefault("19.2")
        @NotBlank
        String bundledVersion();

        @WithDefault("58720256")
        @Min(1)
        long maxUploadBytes();

        @WithDefault("268435456")
        @Min(1)
        long maxBundleBytes();
    }

    interface Storage {

        @WithDefault("data/uploads")
        String uploadDir();
    }

    interface Upload {

        @WithDefault("52428800")
        @Min(1)
        long maxFileSizeBytes();

        @WithDefault("log,txt,json,ndjson,csv")
        List<String> allowedExtensions();

        @WithDefault("text/plain,application/json,text/csv,application/octet-stream")
        List<String> allowedContentTypes();

        @WithDefault("8192")
        @Min(1)
        int sniffBytes();

        @Valid
        RateLimit rateLimit();

        interface RateLimit {

            @WithDefault("20")
            @Min(1)
            int requests();

            @WithDefault("PT1M")
            Duration window();
        }
    }

    interface Ai {

        @WithDefault("anthropic")
        AiProvider provider();

        @NotBlank
        String apiKey();

        Optional<String> model();

        Optional<String> baseUrl();
    }

    interface Security {

        @Valid
        Argon2Settings argon2();

        interface Argon2Settings {

            @WithDefault("19456")
            @Min(8)
            int memoryKib();

            @WithDefault("2")
            @Min(1)
            int iterations();

            @WithDefault("1")
            @Min(1)
            int parallelism();

            @WithDefault("32")
            @Min(16)
            int hashLengthBytes();

            @WithDefault("16")
            @Min(8)
            int saltLengthBytes();
        }
    }

    interface Auth {

        @NotBlank
        String issuer();

        @WithDefault("PT15M")
        Duration accessTtl();

        @WithDefault("P14D")
        Duration refreshTtl();

        Optional<String> bootstrapPassword();

        @Valid
        RateLimit rateLimit();

        interface RateLimit {

            @WithDefault("10")
            @Min(1)
            int attempts();

            @WithDefault("PT15M")
            Duration window();
        }
    }
}
