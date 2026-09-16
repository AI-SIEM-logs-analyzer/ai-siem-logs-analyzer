package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import com.siem.analyzer.search.RecordingEventSearch;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

@QuarkusTest
class EventSearchResourceTest {

    // RecordingEventSearch is a @Mock alternative, so injecting it here swaps the real engine
    // out for the whole class. The engine's own behaviour is proven in the two
    // OpenSearchEventSearch tests; what this class proves is the HTTP contract.
    @Inject RecordingEventSearch search;

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void answersAnEmptyQueryWithAPage() {
        given().when()
                .get("/api/events/search")
                .then()
                .statusCode(200)
                .body("hits", notNullValue())
                .body("totalHits", notNullValue());
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesAPageLargerThanTheCap() {
        given().queryParam("size", 5000).when().get("/api/events/search").then().statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesASubstringLongerThanTheCap() {
        given().queryParam("substring", "a".repeat(300))
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesAnInvertedTimeRange() {
        given().queryParam("from", "2026-09-02T00:00:00Z")
                .queryParam("to", "2026-09-01T00:00:00Z")
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesASeverityThatIsNotOne() {
        given().queryParam("severity", "CATASTROPHIC")
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void reportsTheEngineBeingDownAsUnavailableNotAsEmpty() {
        search.failNextWrites(true);
        try {
            given().when()
                    .get("/api/events/search")
                    .then()
                    .statusCode(503)
                    .body("error", is("search_unavailable"));
        } finally {
            search.reset();
        }
    }
}
