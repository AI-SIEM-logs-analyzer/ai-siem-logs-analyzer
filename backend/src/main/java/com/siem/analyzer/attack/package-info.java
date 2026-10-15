/**
 * MITRE ATT&CK mapping: the Enterprise dataset as reference data, and the techniques each alert
 * evidences.
 *
 * <p>{@link com.siem.analyzer.attack.AttackStixReader} turns the official STIX 2.1 bundle into an
 * {@link com.siem.analyzer.attack.AttackBundle}; {@link
 * com.siem.analyzer.attack.AttackDatasetService} stores it, from the release bundled in the jar or
 * from an administrator's upload. Rules name techniques by ID; {@link
 * com.siem.analyzer.attack.AlertTechniqueResolver} turns an alert into its rule's techniques, or,
 * for an alert without a rule, into those {@link com.siem.analyzer.attack.AttackTypeTechniques}
 * derives from the model's attack type. Depends on {@code repo} and {@code domain}; nothing here
 * calls back into {@code rest}.
 */
package com.siem.analyzer.attack;
