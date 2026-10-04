/**
 * Rule-based detection — conditions over single events and aggregates over a sliding time window.
 *
 * <p>A rule is text in a small expression language, parsed by {@link
 * com.siem.analyzer.detect.RuleExpressionParser} and run by {@link
 * com.siem.analyzer.detect.RuleEngine}. The engine reads {@link
 * com.siem.analyzer.domain.NormalizedEvent}s and nothing else: it has no persistence, no CDI and no
 * clock of its own, so whatever feeds it decides where detection runs and what a {@link
 * com.siem.analyzer.detect.Detection} turns into.
 */
package com.siem.analyzer.detect;
