package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

/**
 * Who may read alerts. The detail asks for an alert that does not exist, so a caller let through
 * gets {@code 404} and one turned away gets {@code 401} or {@code 403}, with nothing to seed.
 */
@QuarkusTest
class AlertResourceSecurityTest {

    private static final long MISSING_ID = 9_999_999L;

    private static ValidatableResponse list() {
        return given().when().get("/api/alerts").then();
    }

    private static ValidatableResponse read() {
        return given().when().get("/api/alerts/" + MISSING_ID).then();
    }

    @Test
    void refusesAnAnonymousCaller() {
        list().statusCode(401);
        read().statusCode(401);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void letsAViewerRead() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "triage", roles = "ANALYST")
    void letsAnAnalystRead() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAnAdministratorRead() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "nobody", roles = "SOMETHING_ELSE")
    void refusesAnUnknownRole() {
        list().statusCode(403);
        read().statusCode(403);
    }
}
