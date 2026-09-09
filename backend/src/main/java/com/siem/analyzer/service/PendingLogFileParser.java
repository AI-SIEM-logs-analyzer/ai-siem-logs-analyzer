package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;
import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

/**
 * The parser this application ships until a real one exists.
 *
 * <p>It reads nothing and writes nothing: the batch stays {@link
 * com.siem.analyzer.domain.LogUploadStatus#PROCESSING}, which is the honest description of a file
 * that has been claimed and not yet parsed. Replacing this bean is the whole of the parser's
 * wiring; the consumer does not change.
 */
@ApplicationScoped
public class PendingLogFileParser implements LogFileParser {

    private static final Logger LOG = Logger.getLogger(PendingLogFileParser.class);

    @Override
    public void parse(LogIngestEvent event) {
        LOG.infof(
                "No parser is installed yet, leaving upload in PROCESSING: uploadId=%d,"
                        + " fileName=%s, storagePath=%s",
                event.uploadId(), event.fileName(), event.storagePath());
    }
}
