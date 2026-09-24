/**
 * Event enrichment. A seam ({@link com.siem.analyzer.enrich.GeoIpEnricher}) and its MaxMind
 * implementation attach geographic and network-owner data to an event's source address while the
 * event is being parsed. Enrichment is additive: a failure here never fails an ingestion batch, it
 * only leaves the event without geo fields.
 */
package com.siem.analyzer.enrich;
