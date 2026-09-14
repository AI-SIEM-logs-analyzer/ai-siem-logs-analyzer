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

/**
 * The upload endpoint as a caller actually reaches it: sign in over HTTP, then carry the issued
 * access token into the multipart upload.
 *
 * <p>{@link LogUploadResourceSecurityTest} and {@link LogUploadValidationTest} cover the same rules
 * with an injected identity ({@code @TestSecurity}) and a synthetic request. What is only provable
 * here is that the two halves agree: the token the login endpoint mints verifies at the upload
 * endpoint, its {@code upn} becomes the stored {@code uploadedBy}, and its {@code groups} decide
 * whether the request is refused. A token minted with the wrong issuer, or a role claim the
 * verifier reads under a different name, would pass both of those tests and fail every one here.
 *
 * <p>Each test signs in as its own freshly created account, because the login and upload counters
 * are keyed on the username and outlive a single test.
 */
@QuarkusTest
class AuthUploadFlowTest {

    private static final String PASSWORD = "an-adequately-long-password";

    private static final byte[] LOG_CONTENT =
            "2026-09-10T10:00:00Z INFO user signed in successfully\n"
                    .getBytes(StandardCharsets.UTF_8);

    @Inject UserService users;

    @Inject AppConfig config;

    /** A username nothing else in the suite will collide with. */
    private static String aUsername() {
        return "flow." + UUID.randomUUID().toString().substring(0, 8);
    }

    /** Creates an account with the given role and returns its username. */
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

    /** Creates an account with the given role, signs in as it, and returns the access token. */
    private String signInAs(Role role) {
        return login(anAccount(role)).then().statusCode(200).extract().path("accessToken");
    }

    private static RequestSpecification as(String token) {
        return given().header("Authorization", "Bearer " + token);
    }

    /**
     * Mints an access token that expired an hour ago.
     *
     * <p>Signed with the same key and stamped with the same issuer as a real one, so the only
     * reason the verifier can refuse it is {@code exp}. Waiting out the configured 15-minute TTL is
     * the alternative, and it is not one.
     */
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

    /** How many uploads the listing holds under a file name. */
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
                        // The upload is attributed to the account that signed in, not to whatever
                        // the request body claimed: the name comes off the token's upn claim.
                        .body("uploadedBy", equalTo(username))
                        .body("checksum", notNullValue())
                        .header("Location", notNullValue())
                        .extract()
                        .response();

        int id = accepted.path("id");

        // The same token reads the metadata back.
        as(token)
                .when()
                .get("/api/logs/uploads/" + id)
                .then()
                .statusCode(200)
                .body("id", equalTo(id))
                .body("fileName", equalTo("flow-happy.log"))
                .body("uploadedBy", equalTo(username));

        // And the upload is findable by the uploader, which is the filter an operator uses.
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

        // A fresh sign-in for the same account is accepted, so the refusal was the age of the
        // token and nothing about the account.
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

        // Reading is what the role is for, and it still works.
        as(token).when().get("/api/logs/uploads").then().statusCode(200);

        // 403 is a refusal, not a partial write: nothing was stored under that name.
        String admin = signInAs(Role.ADMIN);
        org.junit.jupiter.api.Assertions.assertEquals(
                0, storedCountFor(admin, "flow-viewer.log"), "a refused upload was stored");
    }

    @Test
    void refusesAnInvalidFileFromAValidToken() {
        String token = signInAs(Role.ANALYST);

        // Wrong extension.
        as(token)
                .multiPart("file", "flow-payload.exe", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));

        // A log file name over a binary body.
        byte[] gzip = {0x1f, (byte) 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04};
        as(token)
                .multiPart("file", "flow-archive.log", gzip, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415)
                .body("error", equalTo("unsupported_log_file"));

        // Nothing at all.
        as(token)
                .multiPart("file", "flow-empty.log", new byte[0], "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(400);

        // The token survives the refusals: a valid file from the same session is accepted.
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

        // The token has not expired; the deny list is what refuses it.
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

        // Well-formed, signed by nobody this deployment trusts.
        as("not.a.token")
                .multiPart("file", "flow-forged.log", LOG_CONTENT, "text/plain")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(401);
    }
}
