package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.http.ContentType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Who may reach the account endpoints. */
@QuarkusTest
class UserResourceSecurityTest {

    @Test
    void refusesAnAnonymousCaller() {
        given().when().get("/api/users").then().statusCode(401);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void refusesACallerWithoutTheAdministratorRole() {
        given().when().get("/api/users").then().statusCode(403);
    }

    @Test
    @TestSecurity(user = "read.only", roles = "VIEWER")
    void refusesAccountCreationToTheSameCaller() {
        // The read paths are not the dangerous ones. Assert the write path too, because that is
        // the one that could mint an administrator.
        given().contentType(ContentType.JSON)
                .body(
                        Map.of(
                                "username",
                                "should.not.exist",
                                "password",
                                "an-adequately-long-password",
                                "roles",
                                List.of("ADMIN")))
                .when()
                .post("/api/users")
                .then()
                .statusCode(403);
    }
}
