package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

@QuarkusTest
class AlertResourceSecurityTest {

    private static final long MISSING_ID = 9_999_999L;

    private static ValidatableResponse list() {
        return given().when().get("/api/alerts").then();
    }

    private static ValidatableResponse read() {
        return given().when().get("/api/alerts/" + MISSING_ID).then();
    }

    private static ValidatableResponse summarize() {
        return given().when().post("/api/alerts/" + MISSING_ID + "/summary").then();
    }

    @Test
    void refusesAnAnonymousCaller() {
        list().statusCode(401);
        read().statusCode(401);
        summarize().statusCode(401);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void letsAViewerReadButNotSummarise() {
        list().statusCode(200);
        read().statusCode(404);
        summarize().statusCode(403);
    }

    @Test
    @TestSecurity(user = "triage", roles = "ANALYST")
    void letsAnAnalystReadAndSummarise() {
        list().statusCode(200);
        read().statusCode(404);
        summarize().statusCode(404);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAnAdministratorReadAndSummarise() {
        list().statusCode(200);
        read().statusCode(404);
        summarize().statusCode(404);
    }

    @Test
    @TestSecurity(user = "nobody", roles = "SOMETHING_ELSE")
    void refusesAnUnknownRole() {
        list().statusCode(403);
        read().statusCode(403);
        summarize().statusCode(403);
    }
}
