package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestSecurity(user = "admin", roles = "ADMIN")
class LogUploadResourceTest {

    private static final byte[] LOG_CONTENT =
            "2026-09-03T10:00:00Z INFO user admin logged in successfully\n"
                    .getBytes(StandardCharsets.UTF_8);

    @Test
    void uploadsLogFileViaRootPath() {
        Response response =
                given().multiPart("file", "root-sample.log", LOG_CONTENT, "text/plain")
                        .formParam("sourceName", "firewall-main")
                        .formParam("sourceType", "FIREWALL")
                        .when()
                        .post("/logs/upload")
                        .then()
                        .statusCode(202)
                        .body("fileName", equalTo("root-sample.log"))
                        .body("fileSize", equalTo(LOG_CONTENT.length))
                        .body("status", equalTo("PENDING"))
                        .body("uploadedBy", equalTo("admin"))
                        .body("checksum", notNullValue())
                        .body("storagePath", notNullValue())
                        .header("Location", notNullValue())
                        .extract()
                        .response();

        int id = response.path("id");
        assertTrue(id > 0);

        // Read back via GET /logs/upload/{id}
        given().when()
                .get("/logs/upload/" + id)
                .then()
                .statusCode(200)
                .body("id", equalTo(id))
                .body("fileName", equalTo("root-sample.log"))
                .body("status", equalTo("PENDING"));
    }

    @Test
    void uploadsLogFileViaApiPath() {
        Response response =
                given().multiPart("file", "api-sample.log", LOG_CONTENT, "text/plain")
                        .formParam("sourceName", "app-auth")
                        .formParam("sourceType", "APPLICATION")
                        .when()
                        .post("/api/logs/upload")
                        .then()
                        .statusCode(202)
                        .body("fileName", equalTo("api-sample.log"))
                        .body("fileSize", equalTo(LOG_CONTENT.length))
                        .body("status", equalTo("PENDING"))
                        .body("uploadedBy", equalTo("admin"))
                        .extract()
                        .response();

        int id = response.path("id");
        assertTrue(id > 0);

        // Read back via GET /api/logs/uploads/{id}
        given().when()
                .get("/api/logs/uploads/" + id)
                .then()
                .statusCode(200)
                .body("id", equalTo(id))
                .body("fileName", equalTo("api-sample.log"));
    }

    @Test
    void listsRecentUploads() {
        given().multiPart("file", "list-sample.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);

        given().when()
                .get("/api/logs/uploads?limit=10")
                .then()
                .statusCode(200)
                .body("$", notNullValue())
                .body("size()", greaterThan(0));
    }

    @Test
    void rejectsUploadWithMissingOrEmptyFile() {
        // Multipart request with empty file
        given().multiPart("file", "empty.log", new byte[0], "text/plain")
                .formParam("sourceName", "some-source")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(400);

        // Non-multipart request
        given().formParam("sourceName", "some-source")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415);
    }

    @Test
    void rejectsNonExistentSourceId() {
        given().multiPart("file", "source-missing.log", LOG_CONTENT, "text/plain")
                .formParam("sourceId", 999999L)
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(404);
    }

    @Test
    void returns404ForNonExistentUploadId() {
        given().when().get("/api/logs/uploads/999999").then().statusCode(404);
        given().when().get("/logs/upload/999999").then().statusCode(404);
    }
}
