/**
 * Sigma rule import — reads <a href="https://sigmahq.io/">Sigma</a> YAML and converts it into the
 * rule language of {@link com.siem.analyzer.detect.RuleExpressionParser}.
 *
 * <p>{@link com.siem.analyzer.detect.sigma.SigmaConverter} is the entry point. It reads one or more
 * YAML documents with Jackson's YAML module (SnakeYAML underneath), maps Sigma field names onto
 * {@link com.siem.analyzer.detect.EventField}s through a {@link
 * com.siem.analyzer.detect.sigma.SigmaFieldMapping}, and returns each rule as expression text, the
 * same text a person would store in {@code alert_rule.expression}. A rule that cannot be expressed
 * faithfully is skipped with a reason rather than converted into something that means less.
 *
 * <p>Like the rest of {@code detect}, nothing here touches persistence or CDI; storing the result
 * is {@link com.siem.analyzer.service.SigmaRuleImporter}'s job.
 */
package com.siem.analyzer.detect.sigma;
