package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.service.UserService;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import jakarta.inject.Inject;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

@QuarkusTest
class RbacJwtTest {

    private static final long MISSING_ID = 9_999_999L;

    private static final String PASSWORD = "an-adequately-long-password";

    @Inject UserService users;

    private String tokenFor(Role role) {
        String username = "rbac." + UUID.randomUUID().toString().substring(0, 8);
        users.create(username, null, PASSWORD, Set.of(role));

        return given().contentType(ContentType.JSON)
                .body(Map.of("username", username, "password", PASSWORD))
                .when()
                .post("/api/auth/login")
                .then()
                .statusCode(200)
                .extract()
                .path("accessToken");
    }

    private static io.restassured.specification.RequestSpecification as(String token) {
        return given().header("Authorization", "Bearer " + token);
    }

    @Test
    void letsAViewerTokenReadButNotWrite() {
        String token = tokenFor(Role.VIEWER);

        as(token).when().get("/api/users").then().statusCode(200);
        as(token).when().delete("/api/users/" + MISSING_ID).then().statusCode(403);
    }

    @Test
    void letsAnAnalystTokenReadButNotWrite() {
        String token = tokenFor(Role.ANALYST);

        as(token).when().get("/api/users").then().statusCode(200);
        as(token).when().delete("/api/users/" + MISSING_ID).then().statusCode(403);
    }

    @Test
    void letsAnAdministratorTokenReadAndWrite() {
        String token = tokenFor(Role.ADMIN);

        as(token).when().get("/api/users").then().statusCode(200);

        as(token).when().delete("/api/users/" + MISSING_ID).then().statusCode(404);
    }

    @Test
    void reportsTheRolesTheTokenCarries() {
        String token = tokenFor(Role.ANALYST);

        as(token)
                .when()
                .get("/api/auth/me")
                .then()
                .statusCode(200)
                .body("roles", contains("ANALYST"));
    }
}
