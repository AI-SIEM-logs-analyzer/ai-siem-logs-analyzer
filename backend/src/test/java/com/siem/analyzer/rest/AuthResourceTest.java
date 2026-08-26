package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.service.UserService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Sign-in, rotation and sign-out over real HTTP.
 *
 * <p>Each test creates its own account, because the counters and tokens involved are keyed on the
 * username and outlive a single request.
 */
@QuarkusTest
class AuthResourceTest {

    private static final String PASSWORD = "an-adequately-long-password";

    @Inject UserService users;

    private String anAccount() {
        String username = "auth." + UUID.randomUUID().toString().substring(0, 8);
        users.create(username, null, PASSWORD, Set.of(Role.ANALYST));
        return username;
    }

    private static Response login(String username, String password) {
        return given().contentType(ContentType.JSON)
                .body(Map.of("username", username, "password", password))
                .when()
                .post("/api/auth/login");
    }

    private static Response refresh(String refreshToken) {
        return given().contentType(ContentType.JSON)
                .body(Map.of("refreshToken", refreshToken))
                .when()
                .post("/api/auth/refresh");
    }

    @Test
    void issuesATokenPairForValidCredentials() {
        String username = anAccount();

        login(username, PASSWORD)
                .then()
                .statusCode(200)
                .body("accessToken", notNullValue())
                .body("refreshToken", notNullValue())
                .body("tokenType", equalTo("Bearer"))
                .body("expiresIn", equalTo(900));
    }

    @Test
    void answersAWrongPasswordAndAnUnknownUserIdentically() {
        String username = anAccount();

        String wrongPassword = login(username, "not-the-right-password").asString();
        String unknownUser = login("auth.nobody." + UUID.randomUUID(), PASSWORD).asString();

        assertEquals(wrongPassword, unknownUser);
        login(username, "not-the-right-password").then().statusCode(401);
    }

    @Test
    void identifiesTheCallerBehindAnAccessToken() {
        String username = anAccount();
        String access = login(username, PASSWORD).path("accessToken");

        given().header("Authorization", "Bearer " + access)
                .when()
                .get("/api/auth/me")
                .then()
                .statusCode(200)
                .body("username", equalTo(username))
                .body("roles", equalTo(java.util.List.of("ANALYST")));
    }

    @Test
    void refusesTheCurrentAccountEndpointWithoutAToken() {
        given().when().get("/api/auth/me").then().statusCode(401);
    }

    @Test
    void rotatesThePairAndRetiresTheOldRefreshToken() {
        String username = anAccount();
        String firstRefresh = login(username, PASSWORD).path("refreshToken");

        Response rotated = refresh(firstRefresh);

        rotated.then().statusCode(200);
        assertNotEquals(firstRefresh, rotated.path("refreshToken"));
        refresh(firstRefresh).then().statusCode(401);
    }

    @Test
    void treatsAReplayedRefreshTokenAsTheftAndCutsEverySession() {
        String username = anAccount();
        String stolen = login(username, PASSWORD).path("refreshToken");
        String otherSession = login(username, PASSWORD).path("refreshToken");
        refresh(stolen);

        refresh(stolen).then().statusCode(401);

        // The second session was not the one replayed, and is gone all the same.
        refresh(otherSession).then().statusCode(401);
    }

    @Test
    void endsTheSessionImmediatelyOnLogout() {
        String username = anAccount();
        Response session = login(username, PASSWORD);
        String access = session.path("accessToken");
        String refreshToken = session.path("refreshToken");

        given().contentType(ContentType.JSON)
                .header("Authorization", "Bearer " + access)
                .body(Map.of("refreshToken", refreshToken))
                .when()
                .post("/api/auth/logout")
                .then()
                .statusCode(204);

        // The access token has not expired, and is refused anyway.
        given().header("Authorization", "Bearer " + access)
                .when()
                .get("/api/auth/me")
                .then()
                .statusCode(401);
        refresh(refreshToken).then().statusCode(401);
    }

    @Test
    void turnsAwayASignInFloodBeforeCheckingThePassword() {
        String username = anAccount();
        for (int attempt = 0; attempt < 10; attempt++) {
            login(username, "not-the-right-password").then().statusCode(401);
        }

        login(username, "not-the-right-password")
                .then()
                .statusCode(429)
                .header("Retry-After", notNullValue());

        // Still blocked with the right password: the limiter runs before the check.
        login(username, PASSWORD).then().statusCode(429);
    }

    @Test
    void neverReturnsThePasswordOrTheHash() {
        String username = anAccount();

        String payload = login(username, PASSWORD).asString();

        given().contentType(ContentType.JSON)
                .body(Map.of("username", username, "password", PASSWORD))
                .when()
                .post("/api/auth/login")
                .then()
                .body("$", not(org.hamcrest.Matchers.hasKey("passwordHash")));
        org.junit.jupiter.api.Assertions.assertFalse(payload.contains(PASSWORD), payload);
    }
}
