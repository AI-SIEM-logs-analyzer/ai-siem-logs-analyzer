package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

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
    void documentsTheEventSearchContract() {
        String search = "paths.'/api/events/search'.get";
        given().accept("application/json")
                .when()
                .get("/q/openapi")
                .then()
                .statusCode(200)
                .body(search + ".operationId", is("searchEvents"))
                .body(search + ".tags", hasItem("Events"))
                .body(
                        search + ".parameters.name",
                        hasItems(
                                "from",
                                "to",
                                "severity",
                                "srcIp",
                                "status",
                                "order",
                                "size",
                                "cursorOccurredAt",
                                "cursorEventId"))
                .body(
                        search + ".parameters.find { it.name == 'order' }.schema.enum",
                        hasItems("asc", "desc"))
                .body(
                        search + ".parameters.find { it.name == 'severity' }.schema.items.$ref",
                        is("#/components/schemas/Severity"))
                .body("components.schemas.Severity.enum", hasItems("INFO", "CRITICAL"))
                .body(
                        search + ".parameters.find { it.name == 'status' }.schema.items.type",
                        is("string"))
                .body(search + ".responses.keySet()", hasItems("200", "400", "401", "403", "503"))
                .body("components.schemas.EventSearchResponse", notNullValue());
    }

    @Test
    void swaggerUiIsServedOutsideDevMode() {
        given().when().get("/q/swagger-ui").then().statusCode(200);
    }
}
