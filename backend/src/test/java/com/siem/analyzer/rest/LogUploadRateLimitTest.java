package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.security.TestSecurity;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The allowance one account gets on the upload endpoints. Lowered to two uploads for the run, so
 * the limit is reached in three requests rather than twenty-one.
 */
@QuarkusTest
@TestProfile(LogUploadRateLimitTest.TightLimitProfile.class)
@TestSecurity(user = "flooder", roles = "ADMIN")
class LogUploadRateLimitTest {

    private static final int ALLOWED = 2;

    private static final byte[] LOG_CONTENT =
            "2026-09-04T11:00:00Z INFO ok\n".getBytes(StandardCharsets.UTF_8);

    @Test
    void turnsTheAccountAwayOnceItsAllowanceIsSpent() {
        for (int request = 0; request < ALLOWED; request++) {
            given().multiPart("file", "flood-" + request + ".log", LOG_CONTENT, "text/plain")
                    .when()
                    .post("/api/logs/upload")
                    .then()
                    .statusCode(202);
        }

        given().multiPart("file", "flood-over.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(429)
                .header("Retry-After", notNullValue())
                .body("error", equalTo("too_many_uploads"));
    }

    public static class TightLimitProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("app.upload.rate-limit.requests", String.valueOf(ALLOWED));
        }
    }
}
