package com.siem.analyzer.domain;

/** Lifecycle status of an uploaded log file batch. */
public enum LogUploadStatus {

    /** File is stored and metadata recorded, waiting for ingestion processing. */
    PENDING,

    /** Ingestion worker is actively processing the log events. */
    PROCESSING,

    /** All events from the file have been parsed and ingested. */
    INGESTED,

    /** Ingestion failed due to parsing or processing errors. */
    FAILED
}
