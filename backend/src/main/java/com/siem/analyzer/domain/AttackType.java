package com.siem.analyzer.domain;

/**
 * What kind of attack an alert most likely is, as a model judged it.
 *
 * <p>A closed list rather than free text, so the answer can be filtered and counted, and so a
 * provider's structured output can be held to it. Constant names are the values stored in {@code
 * alert.ai_attack_type}, and {@code ck_alert_ai_attack_type} lists exactly these names: adding one
 * is a migration, not a refactor.
 */
public enum AttackType {
    BRUTE_FORCE,
    CREDENTIAL_STUFFING,
    SQL_INJECTION,
    PATH_TRAVERSAL,
    CROSS_SITE_SCRIPTING,
    COMMAND_INJECTION,
    REMOTE_CODE_EXECUTION,
    RECONNAISSANCE,
    DENIAL_OF_SERVICE,
    PRIVILEGE_ESCALATION,
    DATA_EXFILTRATION,
    MALWARE,
    ANOMALOUS_BEHAVIOUR,
    BENIGN,
    OTHER
}
