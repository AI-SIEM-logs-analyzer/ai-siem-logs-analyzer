package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.domain.AttackTactic;
import com.siem.analyzer.domain.AttackTechnique;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The dataset queries. Each test empties the tables inside its own transaction first, which rolls
 * back, so whatever the start-up import loaded is back for the next class.
 */
@QuarkusTest
class AttackTechniqueRepositoryTest {

    @Inject AttackTechniqueRepository techniques;
    @Inject AttackTacticRepository tactics;

    private void seed() {
        techniques.deleteDataset();
        AttackTactic access =
                new AttackTactic(
                        "TA0001",
                        "Initial Access",
                        "initial-access",
                        "https://attack.mitre.org/tactics/TA0001",
                        2);
        AttackTactic credentials =
                new AttackTactic(
                        "TA0006",
                        "Credential Access",
                        "credential-access",
                        "https://attack.mitre.org/tactics/TA0006",
                        1);
        tactics.persist(access);
        tactics.persist(credentials);
        techniques.persist(
                new AttackTechnique(
                        "T1078",
                        "Valid Accounts",
                        null,
                        "https://attack.mitre.org/techniques/T1078",
                        Set.of(access, credentials)));
        techniques.persist(
                new AttackTechnique(
                        "T1110.001",
                        "Password Guessing",
                        "T1110",
                        "https://attack.mitre.org/techniques/T1110/001",
                        Set.of(credentials)));
        techniques.flush();
        techniques.getEntityManager().clear();
    }

    @Test
    @TestTransaction
    void loadsTheKnownTechniquesWithTheirTactics() {
        seed();

        List<AttackTechnique> found = techniques.findWithTactics(List.of("T1078", "T9999"));

        assertEquals(1, found.size());
        assertEquals("Valid Accounts", found.get(0).getName());
        assertEquals(
                Set.of("TA0001", "TA0006"),
                found.get(0).getTactics().stream()
                        .map(AttackTactic::getId)
                        .collect(Collectors.toSet()));
    }

    @Test
    @TestTransaction
    void findsTheTechniquesUnderATactic() {
        seed();

        assertEquals(Set.of("T1078", "T1110.001"), techniques.idsInTactics(List.of("TA0006")));
        assertEquals(Set.of("T1078"), techniques.idsInTactics(List.of("TA0001")));
        assertEquals(Set.of(), techniques.idsInTactics(List.of("TA9999")));
    }

    @Test
    @TestTransaction
    void listsTacticsInMatrixOrder() {
        seed();

        assertEquals(
                List.of("TA0006", "TA0001"),
                tactics.listInMatrixOrder().stream().map(AttackTactic::getId).toList());
    }

    @Test
    @TestTransaction
    void deletingTheDatasetEmptiesItsTables() {
        seed();

        techniques.deleteDataset();

        assertEquals(0, techniques.count());
        assertEquals(0, tactics.count());
    }
}
