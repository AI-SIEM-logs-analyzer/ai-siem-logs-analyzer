/**
 * Line parsers — one per {@link com.siem.analyzer.domain.LogFormat}.
 *
 * <p>A parser here turns one line of text into a {@link com.siem.analyzer.domain.NormalizedEvent}
 * and does nothing else: it reads no files, touches no repository and knows nothing about uploads.
 * That keeps every format testable from a string literal.
 */
package com.siem.analyzer.parse;
