package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;

@QuarkusTest
class AttackResourceSecurityTest {

    private static ValidatableResponse tactics() {
        return given().when().get("/api/attack/tactics").then();
    }

    private static ValidatableResponse techniques() {
        return given().when().get("/api/attack/techniques").then();
    }

    private static ValidatableResponse dataset() {
        return given().when().get("/api/attack/dataset").then();
    }

    private static ValidatableResponse importDataset() {
        return given().contentType("application/json")
                .body("{}")
                .when()
                .post("/api/attack/dataset")
                .then();
    }

    @Test
    void refusesAnAnonymousCaller() {
        tactics().statusCode(401);
        techniques().statusCode(401);
        dataset().statusCode(401);
        importDataset().statusCode(401);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void letsAViewerReadButNotImport() {
        tactics().statusCode(200);
        techniques().statusCode(200);
        dataset().statusCode(200);
        importDataset().statusCode(403);
    }

    @Test
    @TestSecurity(user = "triage", roles = "ANALYST")
    void letsAnAnalystReadButNotImport() {
        tactics().statusCode(200);
        importDataset().statusCode(403);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAnAdministratorImport() {
        tactics().statusCode(200);
        importDataset().statusCode(400);
    }

    @Test
    @TestSecurity(user = "nobody", roles = "SOMETHING_ELSE")
    void refusesAnUnknownRole() {
        tactics().statusCode(403);
        importDataset().statusCode(403);
    }
}
