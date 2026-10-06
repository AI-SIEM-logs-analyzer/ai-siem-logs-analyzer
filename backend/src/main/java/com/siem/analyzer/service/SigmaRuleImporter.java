package com.siem.analyzer.service;

import com.siem.analyzer.detect.sigma.ConvertedRule;
import com.siem.analyzer.detect.sigma.SigmaConverter;
import com.siem.analyzer.detect.sigma.SigmaException;
import com.siem.analyzer.detect.sigma.SigmaImport;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.repo.AlertRuleRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Stores Sigma rules as {@code alert_rule} rows.
 *
 * <p>Conversion is {@link SigmaConverter}'s; this class only decides what happens to each row. A
 * rule is matched to its row by name, which the converter derives from the Sigma title and id, so
 * importing the same file again changes nothing and importing a newer revision of a rule updates
 * its row in place. An update leaves {@code enabled} alone: switching a noisy rule off is an
 * operator's decision that a re-import must not undo.
 *
 * <p>Rules that do not convert are reported, not stored, and do not stop the rest.
 */
@ApplicationScoped
public class SigmaRuleImporter {

    private final AlertRuleRepository rules;
    private final SigmaConverter converter;

    @Inject
    public SigmaRuleImporter(AlertRuleRepository rules) {
        this.rules = rules;
        this.converter = SigmaConverter.withDefaults();
    }

    /**
     * What an import did, by rule name.
     *
     * @param created rules stored for the first time, enabled
     * @param updated rules whose stored row differed and was rewritten
     * @param unchanged rules already stored exactly as converted
     * @param skipped Sigma documents that did not convert, with the reason
     */
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

    /**
     * Converts and stores every rule in a YAML stream of one or more Sigma documents.
     *
     * @throws SigmaException the text is not YAML, or a document in it is not a mapping; nothing is
     *     stored
     */
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
