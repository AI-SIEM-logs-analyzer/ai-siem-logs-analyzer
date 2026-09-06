package com.siem.analyzer.domain;

/**
 * Wire format of an uploaded log file, as detected from its content.
 *
 * <p>This is what the ingestion parser dispatches on, so it describes the shape of the lines, not
 * the MIME type the client declared. The two disagree often: a {@code .json} file arrives as {@code
 * application/octet-stream} from curl, and a {@code text/plain} upload can hold syslog.
 */
public enum LogFormat {

    /** One JSON value per line, or a single JSON array — the first line opens with { or [. */
    JSON,

    /** RFC 3164 or RFC 5424 syslog, with or without the leading priority in angle brackets. */
    SYSLOG,

    /** ArcSight Common Event Format: lines begin with the {@code CEF:} version prefix. */
    CEF,

    /** Comma-separated records, every line holding the same number of fields. */
    CSV,

    /** Free-form text. The fallback: readable lines that match no known structure. */
    PLAIN
}
