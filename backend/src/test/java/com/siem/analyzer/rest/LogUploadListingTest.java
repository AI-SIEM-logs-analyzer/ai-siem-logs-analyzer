package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** Covers the filtered, paged listing at {@code GET /api/logs/uploads}. */
@QuarkusTest
@TestSecurity(user = "admin", roles = "ADMIN")
class LogUploadListingTest {

    private static final byte[] PLAIN_CONTENT =
            "2026-09-03T10:00:00Z INFO user admin logged in successfully\n"
                    .getBytes(StandardCharsets.UTF_8);

    private static final byte[] JSON_CONTENT =
            "{\"ts\":\"2026-09-03T10:00:00Z\",\"msg\":\"logged in\"}\n"
                    .getBytes(StandardCharsets.UTF_8);

    @Test
    void uploadRecordsTheDetectedFormatAndTheUploaderAccount() {
        given().multiPart("file", "listing-format.json", JSON_CONTENT, "application/json")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202)
                .body("detectedFormat", equalTo("JSON"))
                .body("uploadedBy", equalTo("admin"))
                .body("uploadedById", notNullValue())
                .body("updatedAt", notNullValue());
    }

    @Test
    void listingReturnsAPagedEnvelope() {
        upload("listing-envelope.log", PLAIN_CONTENT);

        given().when()
                .get("/api/logs/uploads?page=0&size=5")
                .then()
                .statusCode(200)
                .body("page", equalTo(0))
                .body("size", equalTo(5))
                .body("total", greaterThanOrEqualTo(1))
                .body("items.size()", greaterThanOrEqualTo(1));
    }

    @Test
    void listingFiltersByStatus() {
        upload("listing-status.log", PLAIN_CONTENT);

        given().when()
                .get("/api/logs/uploads?status=PENDING&size=100")
                .then()
                .statusCode(200)
                .body("items.status", everyItem(equalTo("PENDING")));
    }

    @Test
    void listingFiltersByDetectedFormat() {
        upload("listing-json.json", JSON_CONTENT);

        given().when()
                .get("/api/logs/uploads?format=JSON&size=100")
                .then()
                .statusCode(200)
                .body("items.detectedFormat", everyItem(equalTo("JSON")))
                .body("total", greaterThanOrEqualTo(1));
    }

    @Test
    void listingFiltersByUploader() {
        upload("listing-uploader.log", PLAIN_CONTENT);

        given().when()
                .get("/api/logs/uploads?uploadedBy=admin&size=100")
                .then()
                .statusCode(200)
                .body("items.uploadedBy", everyItem(equalTo("admin")))
                .body("total", greaterThanOrEqualTo(1));
    }

    @Test
    void listingClampsAnOversizedPageSize() {
        given().when()
                .get("/api/logs/uploads?size=5000")
                .then()
                .statusCode(200)
                .body("size", equalTo(100));
    }

    @Test
    void listingRejectsANegativePage() {
        given().when().get("/api/logs/uploads?page=-1").then().statusCode(400);
    }

    private void upload(String fileName, byte[] content) {
        given().multiPart("file", fileName, content, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);
    }
}
