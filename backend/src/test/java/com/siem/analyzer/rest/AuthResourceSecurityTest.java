package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Which sign-in endpoints an anonymous caller may reach.
 *
 * <p>The two open endpoints are asserted with a body that fails validation, so a {@code 400} proves
 * the request reached the handler. Asserting on credentials instead would not: a wrong password is
 * answered with {@code 401}, the same status a security refusal carries, and the test would pass
 * whether the endpoint were open or shut.
 */
@QuarkusTest
class AuthResourceSecurityTest {

    private static final Map<String, String> EMPTY_LOGIN = Map.of("username", "", "password", "");

    private static final Map<String, String> EMPTY_REFRESH = Map.of("refreshToken", "");

    @Test
    void letsAnAnonymousCallerReachSignIn() {
        given().contentType(ContentType.JSON)
                .body(EMPTY_LOGIN)
                .when()
                .post("/api/auth/login")
                .then()
                .statusCode(400);
    }

    @Test
    void letsAnAnonymousCallerReachTokenRefresh() {
        given().contentType(ContentType.JSON)
                .body(EMPTY_REFRESH)
                .when()
                .post("/api/auth/refresh")
                .then()
                .statusCode(400);
    }

    @Test
    void refusesSignOutToAnAnonymousCaller() {
        given().contentType(ContentType.JSON)
                .body(EMPTY_REFRESH)
                .when()
                .post("/api/auth/logout")
                .then()
                .statusCode(401);
    }

    @Test
    void refusesTheCurrentAccountToAnAnonymousCaller() {
        given().when().get("/api/auth/me").then().statusCode(401);
    }
}
