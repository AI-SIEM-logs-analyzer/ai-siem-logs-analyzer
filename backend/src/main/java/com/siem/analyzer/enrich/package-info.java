/**
 * Event enrichment, applied while the event is being parsed. Two seams, each with one production
 * implementation: {@link com.siem.analyzer.enrich.GeoIpEnricher} (MaxMind) attaches geographic and
 * network-owner data to an event's source address, and {@link
 * com.siem.analyzer.enrich.UserAgentEnricher} (Yauaa) classifies its User-Agent header into
 * browser, operating system, device class and a bot flag. Enrichment is additive: a failure here
 * never fails an ingestion batch, it only leaves the event without those fields.
 */
package com.siem.analyzer.enrich;
