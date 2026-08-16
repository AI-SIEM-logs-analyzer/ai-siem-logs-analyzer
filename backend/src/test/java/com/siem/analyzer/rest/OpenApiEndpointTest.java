package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

@QuarkusTest
class OpenApiEndpointTest {

    @Test
    void openApiDocumentIsServed() {
        given().when()
                .get("/q/openapi")
                .then()
                .statusCode(200)
                .body(containsString("SIEM Logs Analyzer API"));
    }

    @Test
    void swaggerUiIsServedOutsideDevMode() {
        given().when().get("/q/swagger-ui").then().statusCode(200);
    }
}
