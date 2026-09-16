package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import org.junit.jupiter.api.Test;

@QuarkusTest
class EventSearchResourceSecurityTest {

    @Test
    @TestSecurity(user = "admin", roles = "ADMIN")
    void adminMaySearch() {
        given().when().get("/api/events/search").then().statusCode(200);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void analystMaySearch() {
        given().when().get("/api/events/search").then().statusCode(200);
    }

    @Test
    @TestSecurity(user = "viewer", roles = "VIEWER")
    void viewerMaySearch() {
        given().when().get("/api/events/search").then().statusCode(200);
    }

    @Test
    void anAnonymousCallerMayNot() {
        given().when().get("/api/events/search").then().statusCode(401);
    }
}
