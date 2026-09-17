package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.search.EventQuery;
import com.siem.analyzer.search.IpFilter;
import com.siem.analyzer.search.RecordingEventSearch;
import com.siem.analyzer.search.SortOrder;
import com.siem.analyzer.search.StatusFilter;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import jakarta.inject.Inject;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

@QuarkusTest
class EventSearchResourceTest {

    // RecordingEventSearch is a @Mock alternative, so injecting it here swaps the real engine
    // out for the whole class. The engine's own behaviour is proven in the two
    // OpenSearchEventSearch tests; what this class proves is the HTTP contract.
    @Inject RecordingEventSearch search;

    @AfterEach
    void resetEngine() {
        search.reset();
    }

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
    void passesTheIpStatusAndOrderFiltersToTheEngine() {
        given().queryParam("srcIp", "10.0.0.0/8")
                .queryParam("srcIp", "203.0.113.7")
                .queryParam("status", "5xx")
                .queryParam("status", "404")
                .queryParam("order", "asc")
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(200);

        EventQuery query = search.lastQuery();
        assertEquals(
                Set.of(IpFilter.parse("10.0.0.0/8"), IpFilter.parse("203.0.113.7")),
                query.srcIps());
        assertEquals(
                Set.of(new StatusFilter(500, 599), new StatusFilter(404, 404)), query.statuses());
        assertEquals(SortOrder.ASC, query.order());
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void sortsNewestFirstByDefault() {
        given().when().get("/api/events/search").then().statusCode(200);

        assertEquals(SortOrder.DESC, search.lastQuery().order());
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesAnAddressThatIsNotOne() {
        given().queryParam("srcIp", "example.com")
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesAStatusThatIsNotOne() {
        given().queryParam("status", "7xx").when().get("/api/events/search").then().statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesAnOrderThatIsNotOne() {
        given().queryParam("order", "sideways")
                .when()
                .get("/api/events/search")
                .then()
                .statusCode(400);
    }

    @Test
    @TestSecurity(user = "analyst", roles = "ANALYST")
    void refusesHalfACursor() {
        given().queryParam("cursorEventId", 5)
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
