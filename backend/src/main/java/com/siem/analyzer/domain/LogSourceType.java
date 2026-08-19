package com.siem.analyzer.domain;

/**
 * Kind of system a {@link LogSource} represents.
 *
 * <p>As with {@link Severity}, the constant names are the stored values and the {@code
 * ck_log_source_type} constraint lists them.
 */
public enum LogSourceType {
    SYSLOG,
    FIREWALL,
    CLOUD_TRAIL,
    APPLICATION,
    ENDPOINT
}
