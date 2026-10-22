package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Role;
import com.siem.analyzer.service.UserService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.eclipse.microprofile.jwt.Claims;
import org.junit.jupiter.api.Test;

@QuarkusTest
class AuthUploadFlowTest {

    private static final String PASSWORD = "an-adequately-long-password";

    private static final byte[] LOG_CONTENT =
            "2026-09-10T10:00:00Z INFO user signed in successfully\n"
                    .getBytes(StandardCharsets.UTF_8);

    @Inject UserService users;

    @Inject AppConfig config;

    private static String aUsername() {
        return "flow." + UUID.randomUUID().toString().substring(0, 8);
    }

    private String anAccount(Role role) {
        String username = aUsername();
        users.create(username, null, PASSWORD, Set.of(role));
        return username;
    }

    private static Response login(String username) {
        return given().contentType(ContentType.JSON)
                .body(Map.of("username", username, "password", PASSWORD))
                .when()
                .post("/api/auth/login");
    }

    private String signInAs(Role role) {
        return login(anAccount(role)).then().statusCode(200).extract().path("accessToken");
    }

    private static RequestSpecification as(String token) {
        return given().header("Authorization", "Bearer " + token);
    }

    private String anExpiredToken(String username, Role role) {
        Instant issuedAt = Instant.now().minus(2, ChronoUnit.HOURS);

        return Jwt.issuer(config.auth().issuer())
                .subject(username)
                .upn(username)
                .groups(Set.of(role.name()))
                .claim(Claims.jti.name(), UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plus(1, ChronoUnit.HOURS))
                .sign();
    }

    private static RequestSpecification anUpload(String fileName, byte[] content, String mimeType) {
        return given().multiPart("file", fileName, content, mimeType);
    }

    private static int storedCountFor(String adminToken, String fileName) {
        return as(adminToken)
                .when()
                .get("/api/logs/uploads?size=100")
                .then()
                .statusCode(200)
                .extract()
                .path("items.findAll { it.fileName == '" + fileName + "' }.size()");
    }

    @Test
    void carriesASignInThroughToAStoredUpload() {
        String username = anAccount(Role.ANALYST);
        String token = login(username).then().statusCode(200).extract().path("accessToken");

        Response accepted =
                as(token)
                        .multiPart("file", "flow-happy.log", LOG_CONTENT, "text/plain")
                        .formParam("sourceName", "firewall-main")
                        .formParam("sourceType", "FIREWALL")
                        .when()
                        .post("/api/logs/upload")
                        .then()
                        .statusCode(202)
                        .body("fileName", equalTo("flow-happy.log"))
                        .body("fileSize", equalTo(LOG_CONTENT.length))
                        .body("status", equalTo("PENDING"))
                        .body("uploadedBy", equalTo(username))
                        .body("checksum", notNullValue())
                        .header("Location", notNullValue())
                        .extract()
                        .response();

        int id = accepted.path("id");

        as(token)
                .when()
                .get("/api/logs/uploads/" + id)
                .then()
                .statusCode(200)
                .body("id", equalTo(id))
                .body("fileName", equalTo("flow-happy.log"))
                .body("uploadedBy", equalTo(username));

        as(token)
                .when()
                .get("/api/logs/uploads?uploadedBy=" + username)
                .then()
                .statusCode(200)
                .body("total", equalTo(1))
                .body("items[0].id", equalTo(id));
    }

    @Test
    void refusesAnUploadWhoseTokenHasExpired() {
        String username = anAccount(Role.ANALYST);
        String expired = anExpiredToken(username, Role.ANALYST);

        as(expired)
                .multiPart("file", "flow-expired.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);

        String fresh = login(username).then().statusCode(200).extract().path("accessToken");
        as(fresh)
                .multiPart("file", "flow-expired.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);
    }

    @Test
    void refusesAnUploadFromAViewerToken() {
        String username = anAccount(Role.VIEWER);
        String token = login(username).then().statusCode(200).extract().path("accessToken");

        as(token)
                .multiPart("file", "flow-viewer.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(403);

        as(token)
                .multiPart("file", "flow-viewer.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/logs/upload")
                .then()
                .statusCode(403);

        as(token).when().get("/api/logs/uploads").then().statusCode(200);

        String admin = signInAs(Role.ADMIN);
        org.junit.jupiter.api.Assertions.assertEquals(
                0, storedCountFor(admin, "flow-viewer.log"), "a refused upload was stored");
    }

    @Test
    void refusesAnInvalidFileFromAValidToken() {
        String token = signInAs(Role.ANALYST);

        as(token)
                .multiPart("file", "flow-payload.exe", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));

        byte[] gzip = {0x1f, (byte) 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04};
        as(token)
                .multiPart("file", "flow-archive.log", gzip, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));

        as(token)
                .multiPart("file", "flow-empty.log", new byte[0], "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(400);

        as(token)
                .multiPart("file", "flow-valid.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(202);
    }

    @Test
    void refusesAnUploadWithATokenThatWasSignedOut() {
        String username = anAccount(Role.ANALYST);
        Response session = login(username).then().statusCode(200).extract().response();
        String token = session.path("accessToken");
        String refreshToken = session.path("refreshToken");

        given().contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + token)
                .body(Map.of("refreshToken", refreshToken))
                .when()
                .post("/api/auth/logout")
                .then()
                .statusCode(204);

        as(token)
                .multiPart("file", "flow-logged-out.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);
    }

    @Test
    void refusesAnUploadWithNoTokenOrAForgedOne() {
        anUpload("flow-anon.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);

        as("not.a.token")
                .multiPart("file", "flow-forged.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);
    }
}
