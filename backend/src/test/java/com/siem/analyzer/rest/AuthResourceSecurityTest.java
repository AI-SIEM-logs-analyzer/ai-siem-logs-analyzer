package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import java.util.Map;
import org.junit.jupiter.api.Test;

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
