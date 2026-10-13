package com.siem.analyzer.attack;

/** Where an alert's technique comes from. */
public enum TechniqueSource {
    /** The rule that raised the alert is mapped to it. */
    RULE,
    /**
     * No rule raised the alert; the technique follows from the attack type a model gave it, so it
     * is as good as that classification.
     */
    AI
}
