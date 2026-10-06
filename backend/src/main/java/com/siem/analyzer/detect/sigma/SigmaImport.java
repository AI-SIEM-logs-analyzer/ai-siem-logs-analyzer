package com.siem.analyzer.detect.sigma;

import java.util.List;
import java.util.Objects;

/**
 * What a {@link SigmaConverter} made of a YAML stream.
 *
 * @param rules the rules that converted, in file order, correlations last
 * @param skipped the documents that did not, each with the reason
 */
public record SigmaImport(List<ConvertedRule> rules, List<Skipped> skipped) {

    public SigmaImport {
        rules = List.copyOf(rules);
        skipped = List.copyOf(skipped);
    }

    /**
     * A Sigma document left out of the import.
     *
     * @param title its title, or {@code (untitled)}
     * @param sigmaId its {@code id}; {@code null} when it has none
     * @param reason why, in terms of the Sigma rule
     */
    public record Skipped(String title, String sigmaId, String reason) {

        public Skipped {
            Objects.requireNonNull(title, "title");
            Objects.requireNonNull(reason, "reason");
        }
    }
}
