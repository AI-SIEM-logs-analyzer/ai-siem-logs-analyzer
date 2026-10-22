package com.siem.analyzer.detect.sigma;

import java.util.List;
import java.util.Objects;

public record SigmaImport(List<ConvertedRule> rules, List<Skipped> skipped) {

    public SigmaImport {
        rules = List.copyOf(rules);
        skipped = List.copyOf(skipped);
    }

    public record Skipped(String title, String sigmaId, String reason) {

        public Skipped {
            Objects.requireNonNull(title, "title");
            Objects.requireNonNull(reason, "reason");
        }
    }
}
