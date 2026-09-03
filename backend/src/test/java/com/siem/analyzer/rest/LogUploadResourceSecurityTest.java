package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

@QuarkusTest
class LogUploadResourceSecurityTest {

    private static final byte[] LOG_CONTENT =
            "2026-09-03T10:00:00Z INFO test\n".getBytes(StandardCharsets.UTF_8);

    @Test
    void refusesUploadToAnonymousCaller() {
        given().multiPart("file", "anon.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);

        given().multiPart("file", "anon.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/logs/upload")
                .then()
                .statusCode(401);

        given().when().get("/api/logs/uploads/1").then().statusCode(401);
        given().when().get("/api/logs/uploads").then().statusCode(401);
        given().when().get("/logs/upload/1").then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "viewer", roles = "VIEWER")
    void refusesUploadToViewer() {
        given().multiPart("file", "viewer.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(403);

        given().multiPart("file", "viewer.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/logs/upload")
                .then()
                .statusCode(403);
    }

    @Test
    @TestSecurity(user = "viewer", roles = "VIEWER")
    void letsViewerReadUploads() {
        given().when().get("/api/logs/uploads").then().statusCode(200);
        given().when().get("/api/logs/uploads/999999").then().statusCode(404);
        given().when().get("/logs/upload/999999").then().statusCode(404);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void letsAnalystUploadAndRead() {
        given().multiPart("file", "analyst.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);

        given().multiPart("file", "analyst-root.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/logs/upload")
                .then()
                .statusCode(202);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAdminUploadAndRead() {
        given().multiPart("file", "admin.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);
    }
}
