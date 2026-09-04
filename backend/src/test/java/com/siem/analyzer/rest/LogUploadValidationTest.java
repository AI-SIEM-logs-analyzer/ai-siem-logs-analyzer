package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.security.TestSecurity;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * What the upload endpoints refuse. The size limit is lowered to a few bytes for the run, so the
 * 413 path is exercised without moving 50 MiB through the suite.
 */
@QuarkusTest
@TestProfile(LogUploadValidationTest.SmallLimitProfile.class)
@TestSecurity(user = "validator", roles = "ADMIN")
class LogUploadValidationTest {

    private static final long MAX_SIZE = 64;

    private static final byte[] LOG_CONTENT =
            "2026-09-04T10:00:00Z INFO ok\n".getBytes(StandardCharsets.UTF_8);

    @Test
    void acceptsALogFileWithinTheLimits() {
        given().multiPart("file", "valid.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);
    }

    @Test
    void rejectsAFileOverTheSizeLimit() {
        byte[] tooBig = new byte[(int) MAX_SIZE + 1];
        java.util.Arrays.fill(tooBig, (byte) 'a');

        given().multiPart("file", "big.log", tooBig, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(413)
                .body("error", equalTo("payload_too_large"))
                .body("maxSizeBytes", equalTo((int) MAX_SIZE));
    }

    @Test
    void rejectsADisallowedExtension() {
        given().multiPart("file", "payload.exe", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));
    }

    @Test
    void rejectsADisallowedContentType() {
        given().multiPart("file", "report.log", LOG_CONTENT, "application/pdf")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));
    }

    @Test
    void rejectsABinaryDisguisedAsALogFile() {
        byte[] gzip = {0x1f, (byte) 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04};

        given().multiPart("file", "archive.log", gzip, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));
    }

    @Test
    void appliesTheSameRulesToTheRootPath() {
        given().multiPart("file", "payload.exe", LOG_CONTENT, "text/plain")
                .when()
                .post("/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));
    }

    @Test
    void storesNothingForARejectedUpload() {
        given().multiPart("file", "rejected.exe", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415);

        // A refused upload must leave no metadata behind: validation runs before the file is
        // stored, the row is written or the ingest event is published.
        given().when()
                .get("/api/logs/uploads?limit=100")
                .then()
                .statusCode(200)
                .body("findAll { it.fileName == 'rejected.exe' }.size()", equalTo(0));
    }

    public static class SmallLimitProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("app.upload.max-file-size-bytes", String.valueOf(MAX_SIZE));
        }
    }
}
