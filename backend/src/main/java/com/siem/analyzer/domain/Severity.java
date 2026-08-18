package com.siem.analyzer.domain;

/**
 * How serious an event, rule or alert is.
 *
 * <p>Constant names are the values stored in the database, so renaming one is a migration, not a
 * refactor. The {@code ck_*_severity} constraints in the schema list exactly these names.
 */
public enum Severity {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}
