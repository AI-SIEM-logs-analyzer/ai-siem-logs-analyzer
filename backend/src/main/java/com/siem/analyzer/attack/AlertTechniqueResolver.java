package com.siem.analyzer.attack;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackTactic;
import com.siem.analyzer.domain.AttackTechnique;
import com.siem.analyzer.repo.AlertRuleRepository;
import com.siem.analyzer.repo.AttackTechniqueRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@ApplicationScoped
public class AlertTechniqueResolver {

    public record TacticRef(String id, String name) {}

    public record ResolvedTechnique(
            String id, String name, String url, List<TacticRef> tactics, TechniqueSource source) {

        public ResolvedTechnique {
            tactics = List.copyOf(tactics);
        }
    }

    private record Wanted(Set<String> ids, TechniqueSource source) {}

    private final AlertRuleRepository rules;
    private final AttackTechniqueRepository techniques;

    @Inject
    public AlertTechniqueResolver(AlertRuleRepository rules, AttackTechniqueRepository techniques) {
        this.rules = rules;
        this.techniques = techniques;
    }

    public Map<Long, List<ResolvedTechnique>> resolve(Collection<Alert> alerts) {
        Set<Long> ruleIds = new HashSet<>();
        for (Alert alert : alerts) {
            if (alert.getRule() != null) {
                ruleIds.add(alert.getRule().getId());
            }
        }
        Map<Long, Set<String>> byRule = rules.techniqueIdsByRule(ruleIds);

        Map<Long, Wanted> wanted = new HashMap<>();
        Set<String> allIds = new HashSet<>();
        for (Alert alert : alerts) {
            Wanted techniquesOfAlert = wanted(alert, byRule);
            wanted.put(alert.getId(), techniquesOfAlert);
            allIds.addAll(techniquesOfAlert.ids());
        }

        Map<String, AttackTechnique> known = new HashMap<>();
        for (AttackTechnique technique : techniques.findWithTactics(allIds)) {
            known.put(technique.getId(), technique);
        }

        Map<Long, List<ResolvedTechnique>> resolved = new HashMap<>();
        wanted.forEach(
                (alertId, techniquesOfAlert) ->
                        resolved.put(
                                alertId,
                                techniquesOfAlert.ids().stream()
                                        .sorted()
                                        .map(
                                                id ->
                                                        toResolved(
                                                                id,
                                                                known.get(id),
                                                                techniquesOfAlert.source()))
                                        .toList()));
        return resolved;
    }

    public List<ResolvedTechnique> resolve(Alert alert) {
        return resolve(List.of(alert)).getOrDefault(alert.getId(), List.of());
    }

    private static Wanted wanted(Alert alert, Map<Long, Set<String>> byRule) {
        if (alert.getRule() != null) {
            return new Wanted(
                    byRule.getOrDefault(alert.getRule().getId(), Set.of()), TechniqueSource.RULE);
        }
        if (alert.getAiAttackType() != null) {
            return new Wanted(
                    Set.copyOf(AttackTypeTechniques.of(alert.getAiAttackType())),
                    TechniqueSource.AI);
        }
        return new Wanted(Set.of(), TechniqueSource.RULE);
    }

    private static ResolvedTechnique toResolved(
            String id, AttackTechnique technique, TechniqueSource source) {
        if (technique == null) {
            return new ResolvedTechnique(id, null, null, List.of(), source);
        }
        List<TacticRef> tactics =
                technique.getTactics().stream()
                        .sorted(Comparator.comparingInt(AttackTactic::getOrdinal))
                        .map(tactic -> new TacticRef(tactic.getId(), tactic.getName()))
                        .toList();
        return new ResolvedTechnique(id, technique.getName(), technique.getUrl(), tactics, source);
    }
}
