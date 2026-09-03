package com.siem.analyzer.domain;

import java.time.Instant;

/** Message published to the {@code logs.ingest} Kafka channel when a log upload arrives. */
public record LogIngestEvent(
        Long uploadId,
        Long sourceId,
        String sourceName,
        String sourceType,
        String fileName,
        String contentType,
        long fileSize,
        String checksum,
        String storagePath,
        String uploadedBy,
        Instant uploadedAt) {}
