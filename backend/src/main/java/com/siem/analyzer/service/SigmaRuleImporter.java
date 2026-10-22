package com.siem.analyzer.service;

import com.siem.analyzer.detect.sigma.ConvertedRule;
import com.siem.analyzer.detect.sigma.SigmaConverter;
import com.siem.analyzer.detect.sigma.SigmaImport;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.repo.AlertRuleRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class SigmaRuleImporter {

    private final AlertRuleRepository rules;
    private final SigmaConverter converter;

    @Inject
    public SigmaRuleImporter(AlertRuleRepository rules) {
        this.rules = rules;
        this.converter = SigmaConverter.withDefaults();
    }

    public record Result(
            List<String> created,
            List<String> updated,
            List<String> unchanged,
            List<SigmaImport.Skipped> skipped) {

        public Result {
            created = List.copyOf(created);
            updated = List.copyOf(updated);
            unchanged = List.copyOf(unchanged);
            skipped = List.copyOf(skipped);
        }
    }

    @Transactional
    public Result importRules(String yaml) {
        SigmaImport converted = converter.convert(yaml);
        List<String> created = new ArrayList<>();
        List<String> updated = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        for (ConvertedRule rule : converted.rules()) {
            Optional<AlertRule> stored = rules.findByName(rule.name());
            if (stored.isEmpty()) {
                AlertRule row = new AlertRule();
                rule.applyTo(row);
                rules.persist(row);
                created.add(rule.name());
            } else if (rule.matches(stored.get())) {
                unchanged.add(rule.name());
            } else {
                rule.applyTo(stored.get());
                updated.add(rule.name());
            }
        }
        return new Result(created, updated, unchanged, converted.skipped());
    }
}
