package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.restassured.http.ContentType;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The users API over real HTTP.
 *
 * <p>These tests are not wrapped in a transaction — they go through the HTTP layer, which runs in
 * its own — so each one uses a username of its own and deletes what it created.
 */
@QuarkusTest
@TestSecurity(user = "admin", roles = "ADMIN")
class UserResourceTest {

    private static final String PASSWORD = "an-adequately-long-password";

    private static Map<String, Object> body(String username, List<String> roles) {
        return Map.of("username", username, "password", PASSWORD, "roles", roles);
    }

    private static int create(Map<String, Object> body) {
        return given().contentType(ContentType.JSON)
                .body(body)
                .when()
                .post("/api/users")
                .then()
                .statusCode(201)
                .extract()
                .path("id");
    }

    private static void delete(int id) {
        given().when().delete("/api/users/" + id).then().statusCode(204);
    }

    @Test
    void createsReadsAndDeletesAnAccount() {
        int id = create(body("rest.create", List.of("ANALYST")));
        try {
            given().when()
                    .get("/api/users/" + id)
                    .then()
                    .statusCode(200)
                    .body("username", equalTo("rest.create"))
                    .body("roles", contains("ANALYST"))
                    .body("enabled", equalTo(true))
                    .body("passwordSet", equalTo(true))
                    .body("email", nullValue());
        } finally {
            delete(id);
        }

        given().when().get("/api/users/" + id).then().statusCode(404);
    }

    @Test
    void returnsALocationHeaderPointingAtTheNewAccount() {
        String location =
                given().contentType(ContentType.JSON)
                        .body(body("rest.location", List.of("VIEWER")))
                        .when()
                        .post("/api/users")
                        .then()
                        .statusCode(201)
                        .extract()
                        .header("Location");

        int id = given().when().get(location).then().statusCode(200).extract().path("id");
        delete(id);
    }

    @Test
    void neverReturnsThePasswordOrItsHash() {
        int id = create(body("rest.secret", List.of("VIEWER")));
        try {
            String payload = given().when().get("/api/users/" + id).then().extract().asString();

            given().when()
                    .get("/api/users/" + id)
                    .then()
                    .body("$", not(hasKey("passwordHash")))
                    .body("$", not(hasKey("password")));
            // Belt and braces: the plaintext must not appear anywhere in the response either.
            assertFalse(payload.contains(PASSWORD), payload);
        } finally {
            delete(id);
        }
    }

    @Test
    void listsAccountsIncludingTheSeededAdministrator() {
        int id = create(body("rest.listed", List.of("VIEWER")));
        try {
            given().when()
                    .get("/api/users")
                    .then()
                    .statusCode(200)
                    .body("username", hasItem("admin"))
                    .body("username", hasItem("rest.listed"));
        } finally {
            delete(id);
        }
    }

    @Test
    void reportsThatTheSeededAdministratorHasNoPasswordYet() {
        given().when()
                .get("/api/users")
                .then()
                .statusCode(200)
                .body("find { it.username == 'admin' }.passwordSet", equalTo(false));
    }

    @Test
    void replacesTheMutableFieldsOnUpdate() {
        int id = create(body("rest.update", List.of("VIEWER")));
        try {
            given().contentType(ContentType.JSON)
                    .body(
                            Map.of(
                                    "email",
                                    "updated@example.test",
                                    "roles",
                                    List.of("ADMIN", "ANALYST"),
                                    "enabled",
                                    false))
                    .when()
                    .put("/api/users/" + id)
                    .then()
                    .statusCode(200)
                    .body("email", equalTo("updated@example.test"))
                    .body("roles", contains("ADMIN", "ANALYST"))
                    .body("enabled", equalTo(false))
                    // The username is not part of the update body and must survive it.
                    .body("username", equalTo("rest.update"));
        } finally {
            delete(id);
        }
    }

    @Test
    void changesAPasswordWithoutReturningABody() {
        int id = create(body("rest.password", List.of("ANALYST")));
        try {
            given().contentType(ContentType.JSON)
                    .body(Map.of("password", "a-brand-new-long-password"))
                    .when()
                    .put("/api/users/" + id + "/password")
                    .then()
                    .statusCode(204)
                    .body(emptyOrNullString());
        } finally {
            delete(id);
        }
    }

    @Test
    void rejectsADuplicateUsernameWithAConflict() {
        int id = create(body("rest.duplicate", List.of("VIEWER")));
        try {
            given().contentType(ContentType.JSON)
                    .body(body("rest.duplicate", List.of("VIEWER")))
                    .when()
                    .post("/api/users")
                    .then()
                    .statusCode(409)
                    .body("field", equalTo("username"))
                    .body("message", containsString("already exists"));
        } finally {
            delete(id);
        }
    }

    @Test
    void rejectsAnInvalidBody() {
        // Too short a password.
        given().contentType(ContentType.JSON)
                .body(
                        Map.of(
                                "username",
                                "rest.invalid",
                                "password",
                                "short",
                                "roles",
                                List.of("VIEWER")))
                .when()
                .post("/api/users")
                .then()
                .statusCode(400);

        // No role at all.
        given().contentType(ContentType.JSON)
                .body(Map.of("username", "rest.invalid", "password", PASSWORD, "roles", List.of()))
                .when()
                .post("/api/users")
                .then()
                .statusCode(400);

        // A username with characters that have no business in a login name.
        given().contentType(ContentType.JSON)
                .body(body("rest invalid/../admin", List.of("VIEWER")))
                .when()
                .post("/api/users")
                .then()
                .statusCode(400);

        // A role that is not one of the three.
        given().contentType(ContentType.JSON)
                .body(body("rest.invalid", List.of("SUPERUSER")))
                .when()
                .post("/api/users")
                .then()
                .statusCode(400);
    }

    @Test
    void reportsMissingAccountsAsNotFound() {
        given().when().get("/api/users/999999").then().statusCode(404);
        given().when().delete("/api/users/999999").then().statusCode(404);
        given().contentType(ContentType.JSON)
                .body(Map.of("roles", List.of("VIEWER"), "enabled", true))
                .when()
                .put("/api/users/999999")
                .then()
                .statusCode(404);
        given().contentType(ContentType.JSON)
                .body(Map.of("password", "a-brand-new-long-password"))
                .when()
                .put("/api/users/999999/password")
                .then()
                .statusCode(404);
    }
}
