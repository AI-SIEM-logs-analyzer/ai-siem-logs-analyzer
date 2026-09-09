package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;

/**
 * Turns the stored file an ingest event names into log events.
 *
 * <p>The seam between the consumer and the parsing work: the consumer owns the message and the
 * upload's status, an implementation of this interface owns the file's content. An implementation
 * that finishes the batch is responsible for moving the upload out of {@link
 * com.siem.analyzer.domain.LogUploadStatus#PROCESSING}; one that throws leaves that to the
 * consumer, which records the failure on the row.
 */
public interface LogFileParser {

    /**
     * Parses the file the event names.
     *
     * @throws RuntimeException the file cannot be read or parsed; the consumer marks the upload
     *     failed
     */
    void parse(LogIngestEvent event);
}
