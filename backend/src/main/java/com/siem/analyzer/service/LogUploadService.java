package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.repo.LogSourceRepository;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.security.UploadRateLimiter;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jboss.resteasy.reactive.multipart.FileUpload;

/** Coordinates log file upload, metadata persistence and Kafka ingest message dispatch. */
@ApplicationScoped
public class LogUploadService {

    private final LogUploadRepository uploadRepository;
    private final LogSourceRepository sourceRepository;
    private final LogStorageService storageService;
    private final LogIngestProducer ingestProducer;
    private final LogUploadValidator validator;
    private final UploadRateLimiter rateLimiter;

    @Inject
    public LogUploadService(
            LogUploadRepository uploadRepository,
            LogSourceRepository sourceRepository,
            LogStorageService storageService,
            LogIngestProducer ingestProducer,
            LogUploadValidator validator,
            UploadRateLimiter rateLimiter) {
        this.uploadRepository = uploadRepository;
        this.sourceRepository = sourceRepository;
        this.storageService = storageService;
        this.ingestProducer = ingestProducer;
        this.validator = validator;
        this.rateLimiter = rateLimiter;
    }

    /**
     * Stores the uploaded file, saves metadata to the database, and publishes a message to Kafka
     * {@code logs.ingest}.
     *
     * <p>Both upload endpoints come through here, so the allowance and the file checks live here
     * rather than in either resource. The allowance is charged first: a caller sending one refused
     * file after another still costs the server the reads those checks make, and the limit is what
     * bounds that.
     */
    @Transactional
    public LogUpload upload(
            FileUpload file,
            Long sourceId,
            String sourceName,
            LogSourceType sourceType,
            String uploadedBy) {
        Duration retryAfter = rateLimiter.consume(uploadedBy);
        if (retryAfter != null) {
            throw new UploadRateLimitedException(retryAfter);
        }

        if (file == null || file.filePath() == null) {
            throw new BadRequestException("file part is required");
        }

        validator.validate(file.filePath(), file.fileName(), file.contentType());

        LogStorageService.StoredFile stored;
        try {
            stored = storageService.store(file);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage());
        }

        LogSource source = null;
        if (sourceId != null) {
            source =
                    sourceRepository
                            .findByIdOptional(sourceId)
                            .orElseThrow(
                                    () ->
                                            new NotFoundException(
                                                    "no log source with id " + sourceId));
        } else if (sourceName != null && !sourceName.isBlank()) {
            source = sourceRepository.findByName(sourceName).orElse(null);
        }

        LogUpload upload = new LogUpload();
        upload.setSource(source);
        upload.setFileName(
                stored.originalFileName() != null ? stored.originalFileName() : "uploaded.log");
        upload.setContentType(stored.contentType());
        upload.setFileSize(stored.size());
        upload.setChecksumSha256(stored.checksum());
        upload.setStoragePath(stored.storagePath());
        upload.setStatus(LogUploadStatus.PENDING);
        upload.setUploadedBy(uploadedBy);
        upload.setCreatedAt(Instant.now());

        uploadRepository.persist(upload);

        String typeStr =
                source != null
                        ? source.getType().name()
                        : (sourceType != null ? sourceType.name() : null);

        LogIngestEvent event =
                new LogIngestEvent(
                        upload.getId(),
                        source != null ? source.getId() : sourceId,
                        source != null ? source.getName() : sourceName,
                        typeStr,
                        upload.getFileName(),
                        upload.getContentType(),
                        upload.getFileSize(),
                        upload.getChecksumSha256(),
                        upload.getStoragePath(),
                        upload.getUploadedBy(),
                        upload.getCreatedAt());

        ingestProducer.publish(event);

        return upload;
    }

    public Optional<LogUpload> findById(Long id) {
        return uploadRepository.findByIdOptional(id);
    }

    public List<LogUpload> listRecent(int limit) {
        return uploadRepository.listRecent(limit);
    }
}
