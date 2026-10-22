package com.siem.analyzer.detect;

import java.util.Objects;

public record RuleExpression(Condition condition, WindowSpec window) {

    public RuleExpression {
        Objects.requireNonNull(condition, "condition");
    }

    public boolean isWindowed() {
        return window != null;
    }
}
