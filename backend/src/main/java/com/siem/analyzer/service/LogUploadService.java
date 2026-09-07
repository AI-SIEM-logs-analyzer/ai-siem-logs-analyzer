package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.repo.LogSourceRepository;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.repo.UserRepository;
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

    /**
     * Longest error text kept on a failed upload.
     *
     * <p>A parser can fail with a stack trace thousands of characters long. The first two thousand
     * carry the message and the frame that matters; the rest belongs in the logs, not in a column
     * every listing reads.
     */
    public static final int MAX_ERROR_MESSAGE_LENGTH = 2000;

    private final LogUploadRepository uploadRepository;
    private final LogSourceRepository sourceRepository;
    private final UserRepository userRepository;
    private final LogStorageService storageService;
    private final LogIngestProducer ingestProducer;
    private final LogUploadValidator validator;
    private final LogFormatDetector formatDetector;
    private final UploadRateLimiter rateLimiter;

    @Inject
    public LogUploadService(
            LogUploadRepository uploadRepository,
            LogSourceRepository sourceRepository,
            UserRepository userRepository,
            LogStorageService storageService,
            LogIngestProducer ingestProducer,
            LogUploadValidator validator,
            LogFormatDetector formatDetector,
            UploadRateLimiter rateLimiter) {
        this.uploadRepository = uploadRepository;
        this.sourceRepository = sourceRepository;
        this.userRepository = userRepository;
        this.storageService = storageService;
        this.ingestProducer = ingestProducer;
        this.validator = validator;
        this.formatDetector = formatDetector;
        this.rateLimiter = rateLimiter;
    }

    /**
     * Stores the uploaded file, saves metadata to the database, and publishes a message to Kafka
     * {@code logs.ingest}.
     *
     * <p>The message leaves only once this transaction commits; see {@link LogIngestProducer}. A
     * failure anywhere below therefore takes the event with it, rather than pointing a consumer at
     * a row that was rolled back.
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

        // Detected on the spooled part rather than after the copy: it is the same bytes, and a
        // failure here must not leave a stored file with no row pointing at it.
        LogFormat detectedFormat = formatDetector.detect(file.filePath(), file.fileName());

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
        upload.setDetectedFormat(detectedFormat);
        upload.setUploadedBy(uploadedBy);
        // Null when the upload came from a token whose account has since been removed. The
        // username text above still records who it was.
        upload.setUploadedByUser(
                uploadedBy != null ? userRepository.findByUsername(uploadedBy).orElse(null) : null);
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

    /**
     * Marks an upload as being ingested.
     *
     * @throws NotFoundException no upload has that id
     * @throws IllegalUploadTransitionException the upload is not {@link LogUploadStatus#PENDING}
     */
    @Transactional
    public LogUpload markProcessing(Long id) {
        LogUpload upload = requireUpload(id);
        requireStatus(upload, LogUploadStatus.PROCESSING, LogUploadStatus.PENDING);

        upload.setStatus(LogUploadStatus.PROCESSING);
        upload.setProcessingStartedAt(Instant.now());
        return upload;
    }

    /**
     * Marks an ingestion as finished and records how many events came out of the file.
     *
     * @throws NotFoundException no upload has that id
     * @throws IllegalUploadTransitionException the upload is not {@link LogUploadStatus#PROCESSING}
     */
    @Transactional
    public LogUpload markIngested(Long id, long eventCount) {
        LogUpload upload = requireUpload(id);
        requireStatus(upload, LogUploadStatus.INGESTED, LogUploadStatus.PROCESSING);

        upload.setStatus(LogUploadStatus.INGESTED);
        upload.setEventCount(eventCount);
        upload.setProcessedAt(Instant.now());
        return upload;
    }

    /**
     * Marks an ingestion as failed and records why.
     *
     * <p>Reachable from PENDING as well as PROCESSING: a batch can fail before any worker claims
     * it, when the stored file cannot be read or the ingest message cannot be handled at all.
     *
     * @throws NotFoundException no upload has that id
     * @throws IllegalUploadTransitionException the upload already reached a terminal status
     */
    @Transactional
    public LogUpload markFailed(Long id, String errorMessage) {
        LogUpload upload = requireUpload(id);
        requireStatus(
                upload,
                LogUploadStatus.FAILED,
                LogUploadStatus.PENDING,
                LogUploadStatus.PROCESSING);

        upload.setStatus(LogUploadStatus.FAILED);
        upload.setErrorMessage(truncate(errorMessage));
        upload.setProcessedAt(Instant.now());
        return upload;
    }

    private LogUpload requireUpload(Long id) {
        return uploadRepository
                .findByIdOptional(id)
                .orElseThrow(() -> new NotFoundException("no log upload with id " + id));
    }

    private static void requireStatus(
            LogUpload upload, LogUploadStatus target, LogUploadStatus... allowedCurrent) {
        for (LogUploadStatus allowed : allowedCurrent) {
            if (upload.getStatus() == allowed) {
                return;
            }
        }
        throw new IllegalUploadTransitionException(upload.getId(), upload.getStatus(), target);
    }

    private static String truncate(String errorMessage) {
        if (errorMessage == null || errorMessage.length() <= MAX_ERROR_MESSAGE_LENGTH) {
            return errorMessage;
        }
        return errorMessage.substring(0, MAX_ERROR_MESSAGE_LENGTH);
    }

    public Optional<LogUpload> findById(Long id) {
        return uploadRepository.findByIdOptional(id);
    }

    /** Returns one page of uploads matching the filter, newest first. */
    public List<LogUpload> search(LogUploadRepository.Filter filter, int page, int size) {
        return uploadRepository.search(filter, page, size);
    }

    /** Counts every upload matching the filter, across all pages. */
    public long count(LogUploadRepository.Filter filter) {
        return uploadRepository.count(filter);
    }
}
