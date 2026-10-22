package com.siem.analyzer.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import com.siem.analyzer.attack.AttackDatasetService;
import com.siem.analyzer.attack.AttackFixtures;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestSecurity(user = "admin", roles = "ADMIN")
class AttackResourceTest {

    @Inject AttackDatasetService datasets;
    @Inject EntityManager entityManager;

    @Test
    void listsTacticsInMatrixOrder() {
        given().when()
                .get("/api/attack/tactics")
                .then()
                .statusCode(200)
                .body("id", equalTo(List.of("TA0043", "TA0001", "TA0006", "TA0005", "TA0007")))
                .body("[2].name", equalTo("Credential Access"))
                .body("[2].shortname", equalTo("credential-access"));
    }

    @Test
    void listsEveryTechniqueWithItsTactics() {
        given().when()
                .get("/api/attack/techniques")
                .then()
                .statusCode(200)
                .body("size()", equalTo(AttackFixtures.TECHNIQUE_COUNT))
                .body("find { it.id == 'T1078' }.tactics.id", equalTo(List.of("TA0001", "TA0005")))
                .body("find { it.id == 'T1110.001' }.parentId", equalTo("T1110"));
    }

    @Test
    void listsOnlyTheTechniquesInUse() {
        given().when()
                .get("/api/attack/techniques?inUse=true")
                .then()
                .statusCode(200)
                .body("id", hasItems("T1110.001", "T1190", "T1083", "T1595.002", "T1595.003"))
                .body("id", hasItems("T1110", "T1059"))
                .body("find { it.id == 'T1059' }.name", nullValue())
                .body("id", not(hasItem("T1078")));
    }

    @Test
    void showsTheLoadedDataset() {
        given().when()
                .get("/api/attack/dataset")
                .then()
                .statusCode(200)
                .body("version", equalTo("0.1"))
                .body("techniqueCount", equalTo(AttackFixtures.TECHNIQUE_COUNT));
    }

    @Test
    void importsAnUploadedBundlePlainOrGzipped() {
        given().contentType("application/json")
                .body(AttackFixtures.bytes())
                .when()
                .post("/api/attack/dataset")
                .then()
                .statusCode(200)
                .body("version", equalTo("0.1"))
                .body("techniqueCount", equalTo(AttackFixtures.TECHNIQUE_COUNT));
        given().contentType("application/gzip")
                .body(AttackFixtures.gzip(AttackFixtures.bytes()))
                .when()
                .post("/api/attack/dataset")
                .then()
                .statusCode(200)
                .body("version", equalTo("0.1"));
    }

    @Test
    void refusesAnInvalidBundleAndKeepsTheDataset() {
        given().contentType("application/json")
                .body("{\"type\":\"report\",\"objects\":[]}")
                .when()
                .post("/api/attack/dataset")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_attack_bundle"));

        given().when().get("/api/attack/dataset").then().body("version", equalTo("0.1"));
    }

    @Test
    void answers404WhenNothingWasImported() {
        QuarkusTransaction.requiringNew()
                .run(
                        () ->
                                entityManager
                                        .createNativeQuery("delete from attack_dataset")
                                        .executeUpdate());
        try {
            given().when().get("/api/attack/dataset").then().statusCode(404);
        } finally {
            datasets.importUpload(new ByteArrayInputStream(AttackFixtures.bytes()));
        }
    }
}
