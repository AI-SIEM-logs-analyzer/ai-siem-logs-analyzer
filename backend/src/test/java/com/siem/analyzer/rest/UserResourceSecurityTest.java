package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.http.ContentType;
import io.restassured.response.ValidatableResponse;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Who may reach the account endpoints.
 *
 * <p>Every case here aims at an account id that does not exist. A caller that is allowed through
 * therefore gets {@code 404} and one that is not gets {@code 403}, which separates the two answers
 * without any fixture to set up or clean up. The one exception is account creation, which has no id
 * to miss and so creates and removes a throwaway account.
 */
@QuarkusTest
class UserResourceSecurityTest {

    /** Outside the range the suite's sequences reach, so every lookup for it misses. */
    private static final long MISSING_ID = 9_999_999L;

    private static final String PASSWORD = "an-adequately-long-password";

    private static ValidatableResponse list() {
        return given().when().get("/api/users").then();
    }

    private static ValidatableResponse read() {
        return given().when().get("/api/users/" + MISSING_ID).then();
    }

    private static ValidatableResponse create() {
        return given().contentType(ContentType.JSON)
                .body(
                        Map.of(
                                "username",
                                "sec." + UUID.randomUUID().toString().substring(0, 8),
                                "password",
                                PASSWORD,
                                // An administrator is what a privilege escalation would reach
                                // for, so that is what the refused calls ask for.
                                "roles",
                                List.of("ADMIN")))
                .when()
                .post("/api/users")
                .then();
    }

    private static ValidatableResponse update() {
        return given().contentType(ContentType.JSON)
                .body(Map.of("roles", List.of("ADMIN"), "enabled", true))
                .when()
                .put("/api/users/" + MISSING_ID)
                .then();
    }

    private static ValidatableResponse changePassword() {
        return given().contentType(ContentType.JSON)
                .body(Map.of("password", PASSWORD))
                .when()
                .put("/api/users/" + MISSING_ID + "/password")
                .then();
    }

    private static ValidatableResponse delete() {
        return given().when().delete("/api/users/" + MISSING_ID).then();
    }

    @Test
    void refusesEveryEndpointToAnAnonymousCaller() {
        list().statusCode(401);
        read().statusCode(401);
        create().statusCode(401);
        update().statusCode(401);
        changePassword().statusCode(401);
        delete().statusCode(401);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void letsAViewerReadAccounts() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void refusesEveryWriteToAViewer() {
        create().statusCode(403);
        update().statusCode(403);
        changePassword().statusCode(403);
        delete().statusCode(403);
    }

    @Test
    @TestSecurity(user = "triage", roles = "ANALYST")
    void letsAnAnalystReadAccounts() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "triage", roles = "ANALYST")
    void refusesEveryWriteToAnAnalyst() {
        create().statusCode(403);
        update().statusCode(403);
        changePassword().statusCode(403);
        delete().statusCode(403);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAnAdministratorReadAccounts() {
        list().statusCode(200);
        read().statusCode(404);
    }

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void letsAnAdministratorWriteAccounts() {
        int id = create().statusCode(201).extract().path("id");
        given().when().delete("/api/users/" + id).then().statusCode(204);

        update().statusCode(404);
        changePassword().statusCode(404);
        delete().statusCode(404);
    }
}
