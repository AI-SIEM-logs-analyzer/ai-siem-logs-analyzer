/**
 * Anomaly scoring — an Isolation Forest trained on a baseline of normal traffic.
 *
 * <p>Where the rules in {@link com.siem.analyzer.detect} say what an attack looks like, this
 * package learns what ordinary traffic looks like and scores how far an event strays from it. Each
 * HTTP event becomes three numbers ({@link com.siem.analyzer.detect.anomaly.EventFeatures}): how
 * many requests its source address sent within the rate window, the response size, and the status
 * code. {@link com.siem.analyzer.detect.anomaly.AnomalyBaseline#train} fits Smile's isolation trees
 * to a baseline of those and calibrates a threshold on it; an {@link
 * com.siem.analyzer.detect.anomaly.AnomalyScorer} then scores new events against that baseline.
 *
 * <p>Like the rule engine, nothing here has persistence, CDI or a clock of its own: it reads {@link
 * com.siem.analyzer.domain.NormalizedEvent}s and returns {@link
 * com.siem.analyzer.detect.anomaly.AnomalyScore}s, and whatever feeds it decides where the baseline
 * comes from and what an anomaly turns into.
 */
package com.siem.analyzer.detect.anomaly;
