package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static io.restassured.RestAssured.withArgs;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.oneOf;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.repo.AlertRuleRepository;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import jakarta.inject.Inject;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Covers the listing and detail at {@code /api/alerts}.
 *
 * <p>The rows are committed, since the request reads them in a transaction of its own, and removed
 * after each test: an event left behind would sit in the search backlog that {@code
 * EventIndexerTest} and {@code SearchBackfillJobTest} expect to find empty.
 */
@QuarkusTest
@TestSecurity(user = "triage", roles = "ANALYST")
class AlertResourceTest {

    @Inject AlertRepository alerts;
    @Inject AlertRuleRepository rules;
    @Inject LogEventRepository events;
    @Inject LogSourceRepository sources;

    private long critical;
    private long warning;
    private long eventId;
    private long ruleId;
    private long sourceId;

    @BeforeEach
    void seed() {
        QuarkusTransaction.requiringNew()
                .run(
                        () -> {
                            String suffix = UUID.randomUUID().toString().substring(0, 8);
                            LogSource source = new LogSource();
                            source.setName("alerts-" + suffix);
                            source.setType(LogSourceType.APPLICATION);
                            sources.persist(source);
                            sourceId = source.getId();

                            LogEvent event = new LogEvent();
                            event.setSource(source);
                            event.setOccurredAt(Instant.parse("2026-10-01T10:00:05Z"));
                            event.setSeverity(Severity.WARNING);
                            event.setMessage("POST /login 401");
                            event.setRaw("10.0.0.7 - - \"POST /login HTTP/1.1\" 401 12");
                            event.setPayload(
                                    Map.of(
                                            "srcIp",
                                            "10.0.0.7",
                                            "method",
                                            "POST",
                                            "status",
                                            401,
                                            "attributes",
                                            Map.of("tenant", "acme")));
                            events.persist(event);
                            eventId = event.getId();

                            AlertRule rule = new AlertRule();
                            rule.setName("brute-force-" + suffix);
                            rule.setSeverity(Severity.CRITICAL);
                            rule.setExpression("status = 401");
                            rule.setTechniqueIds(List.of("T1110.001"));
                            rules.persist(rule);
                            ruleId = rule.getId();

                            Alert grouped = new Alert();
                            grouped.setRule(rule);
                            grouped.setLogEvent(event);
                            grouped.setTitle(rule.getName());
                            grouped.setDetail("count = 6 (>= 5) within 1m for srcIp=10.0.0.7");
                            grouped.setSeverity(Severity.CRITICAL);
                            Map<String, Object> group = new LinkedHashMap<>();
                            group.put("srcIp", "10.0.0.7");
                            grouped.setGroupKey(group);
                            grouped.setAggregateValue(BigDecimal.valueOf(6));
                            grouped.setEventCount(6);
                            grouped.setWindowStart(Instant.parse("2026-10-01T10:00:00Z"));
                            grouped.setWindowEnd(Instant.parse("2026-10-01T10:00:05Z"));
                            alerts.persist(grouped);
                            critical = grouped.getId();

                            Alert closed = new Alert();
                            closed.setLogEvent(event);
                            closed.setTitle("model-" + suffix);
                            closed.setSeverity(Severity.WARNING);
                            // No rule fired; the model read it as credential stuffing.
                            closed.recordAiSummary(
                                    Severity.WARNING,
                                    AttackType.CREDENTIAL_STUFFING,
                                    "Logins with leaked pairs",
                                    "Reset the accounts",
                                    List.of(),
                                    "test/model",
                                    Instant.parse("2026-10-01T10:01:00Z"));
                            alerts.persist(closed);
                            closed.changeStatus(AlertStatus.RESOLVED, Instant.now());
                            warning = closed.getId();
                        });
    }

    @AfterEach
    void cleanUp() {
        QuarkusTransaction.requiringNew()
                .run(
                        () -> {
                            alerts.delete("id in ?1", List.of(critical, warning));
                            rules.deleteById(ruleId);
                            events.deleteById(eventId);
                            sources.deleteById(sourceId);
                        });
    }

    @Test
    void listsAlertsNewestFirstInAPagedEnvelope() {
        given().when()
                .get("/api/alerts?size=5")
                .then()
                .statusCode(200)
                .body("page", equalTo(0))
                .body("size", equalTo(5))
                .body("total", greaterThanOrEqualTo(2))
                // The later of the two seeded alerts was raised last.
                .body("items[0].id", equalTo((int) warning));
    }

    @Test
    void filtersBySeverity() {
        given().when()
                .get("/api/alerts?severity=critical&size=100")
                .then()
                .statusCode(200)
                .body("items.severity", everyItem(equalTo("CRITICAL")))
                .body("items.id", hasItem((int) critical))
                .body("items.id", not(hasItem((int) warning)));
    }

    @Test
    void repeatedValuesCombineWithOr() {
        given().when()
                .get("/api/alerts?severity=CRITICAL&severity=WARNING&size=100")
                .then()
                .statusCode(200)
                .body("items.severity", everyItem(oneOf("CRITICAL", "WARNING")))
                .body("items.id", hasItem((int) critical))
                .body("items.id", hasItem((int) warning));
    }

    @Test
    void filtersByStatus() {
        given().when()
                .get("/api/alerts?status=RESOLVED&size=100")
                .then()
                .statusCode(200)
                .body("items.status", everyItem(equalTo("RESOLVED")))
                .body("items.id", hasItem((int) warning))
                .body("items.id", not(hasItem((int) critical)));
    }

    @Test
    void clampsThePageSize() {
        given().when()
                .get("/api/alerts?size=1000")
                .then()
                .statusCode(200)
                .body("size", equalTo(100));
    }

    @Test
    void refusesAnUnknownSeverityOrStatus() {
        given().when().get("/api/alerts?severity=URGENT").then().statusCode(400);
        given().when().get("/api/alerts?status=OPEN").then().statusCode(400);
        given().when().get("/api/alerts?page=-1").then().statusCode(400);
    }

    @Test
    void showsOneAlertWithTheDetectionAndItsTriggeringEvent() {
        given().when()
                .get("/api/alerts/" + critical)
                .then()
                .statusCode(200)
                .body("severity", equalTo("CRITICAL"))
                .body("status", equalTo("NEW"))
                .body("ruleId", equalTo((int) ruleId))
                .body("groupKey.srcIp", equalTo("10.0.0.7"))
                .body("eventCount", equalTo(6))
                .body("aggregateValue", equalTo(6))
                .body("windowStart", equalTo("2026-10-01T10:00:00Z"))
                .body("windowEnd", equalTo("2026-10-01T10:00:05Z"))
                .body("trigger.eventId", equalTo((int) eventId))
                .body("trigger.message", equalTo("POST /login 401"))
                .body("trigger.fields.srcIp", equalTo("10.0.0.7"))
                .body("trigger.fields.status", equalTo(401))
                .body("trigger.fields.attributes.tenant", equalTo("acme"));
    }

    @Test
    void showsAnAlertWithoutARule() {
        given().when()
                .get("/api/alerts/" + warning)
                .then()
                .statusCode(200)
                .body("ruleId", nullValue())
                .body("status", equalTo("RESOLVED"))
                .body("resolvedAt", not(nullValue()))
                .body("groupKey", nullValue());
    }

    @Test
    void answers404ForAMissingAlert() {
        given().when().get("/api/alerts/9999999").then().statusCode(404);
    }

    @Test
    void showsTheTechniquesOfTheRuleThatFired() {
        given().when()
                .get("/api/alerts/" + critical)
                .then()
                .statusCode(200)
                .body("techniques.size()", equalTo(1))
                .body("techniques[0].id", equalTo("T1110.001"))
                .body("techniques[0].name", equalTo("Password Guessing"))
                .body("techniques[0].url", equalTo("https://attack.mitre.org/techniques/T1110/001"))
                .body("techniques[0].tactics[0].id", equalTo("TA0006"))
                .body("techniques[0].tactics[0].name", equalTo("Credential Access"))
                .body("techniques[0].source", equalTo("RULE"));
    }

    @Test
    void derivesTechniquesFromTheModelsAttackTypeWhenNoRuleFired() {
        given().when()
                .get("/api/alerts/" + warning)
                .then()
                .statusCode(200)
                .body("techniques.id", equalTo(List.of("T1110.004")))
                .body("techniques[0].source", equalTo("AI"));
    }

    @Test
    void listsTheTechniquesOnEveryRow() {
        given().when()
                .get("/api/alerts?size=100")
                .then()
                .statusCode(200)
                .body(
                        "items.find { it.id == %s }.techniques.id",
                        withArgs((int) critical), equalTo(List.of("T1110.001")))
                .body(
                        "items.find { it.id == %s }.techniques.id",
                        withArgs((int) warning), equalTo(List.of("T1110.004")));
    }

    @Test
    void aBaseTechniqueFilterMatchesItsSubTechniquesFromRulesAndModels() {
        given().when()
                .get("/api/alerts?technique=T1110&size=100")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) critical))
                .body("items.id", hasItem((int) warning));
    }

    @Test
    void aSubTechniqueFilterMatchesOnlyThatSubTechnique() {
        given().when()
                .get("/api/alerts?technique=T1110.001&size=100")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) critical))
                .body("items.id", not(hasItem((int) warning)));
    }

    @Test
    void filtersByTactic() {
        given().when()
                .get("/api/alerts?tactic=TA0006&size=100")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) critical))
                .body("items.id", hasItem((int) warning));
        given().when()
                .get("/api/alerts?tactic=TA0043&size=100")
                .then()
                .statusCode(200)
                .body("items.id", not(hasItem((int) critical)))
                .body("items.id", not(hasItem((int) warning)));
    }

    @Test
    void aTacticWithNoMappedTechniqueMatchesNothing() {
        given().when()
                .get("/api/alerts?tactic=TA9999")
                .then()
                .statusCode(200)
                .body("total", equalTo(0))
                .body("items.size()", equalTo(0));
    }

    @Test
    void attackFiltersCombineWithTheOthersByAnd() {
        given().when()
                .get("/api/alerts?technique=T1110&severity=CRITICAL&size=100")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) critical))
                .body("items.id", not(hasItem((int) warning)));
    }

    @Test
    void acceptsLowerCaseAndPaddedIds() {
        given().when()
                .get("/api/alerts?technique=t1110.004&size=100")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) warning))
                .body("items.id", not(hasItem((int) critical)));
        given().queryParam("tactic", " ta0006 ")
                .queryParam("size", 100)
                .when()
                .get("/api/alerts")
                .then()
                .statusCode(200)
                .body("items.id", hasItem((int) critical));
    }

    @Test
    void refusesAMalformedTechniqueOrTactic() {
        given().when().get("/api/alerts?technique=T110").then().statusCode(400);
        given().when().get("/api/alerts?technique=T1110.1").then().statusCode(400);
        given().when().get("/api/alerts?tactic=TA6").then().statusCode(400);
        given().when().get("/api/alerts?tactic=T1110").then().statusCode(400);
    }
}
