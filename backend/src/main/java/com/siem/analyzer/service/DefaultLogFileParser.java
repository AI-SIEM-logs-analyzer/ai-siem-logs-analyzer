package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.enrich.GeoIpEnricher;
import com.siem.analyzer.enrich.UserAgentEnricher;
import com.siem.analyzer.parse.AccessLogParser;
import com.siem.analyzer.parse.JsonLogParser;
import com.siem.analyzer.parse.SyslogParser;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.search.EventIndexer;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Parses uploaded log files line by line, persists normalized events into PostgreSQL, indexes them
 * into the search store via {@link EventIndexer}, and marks the upload as ingested.
 */
@ApplicationScoped
public class DefaultLogFileParser implements LogFileParser {

    private static final Logger LOG = Logger.getLogger(DefaultLogFileParser.class);

    private final LogUploadService uploadService;
    private final LogUploadRepository uploadRepository;
    private final LogSourceRepository sourceRepository;
    private final LogEventRepository eventRepository;
    private final EventIndexer eventIndexer;
    private final LogFormatDetector formatDetector;
    private final AccessLogParser accessLogParser;
    private final SyslogParser syslogParser;
    private final JsonLogParser jsonLogParser;
    private final AppConfig appConfig;
    private final GeoIpEnricher geoIpEnricher;
    private final UserAgentEnricher userAgentEnricher;

    @Inject
    public DefaultLogFileParser(
            LogUploadService uploadService,
            LogUploadRepository uploadRepository,
            LogSourceRepository sourceRepository,
            LogEventRepository eventRepository,
            EventIndexer eventIndexer,
            LogFormatDetector formatDetector,
            AccessLogParser accessLogParser,
            SyslogParser syslogParser,
            JsonLogParser jsonLogParser,
            AppConfig appConfig,
            GeoIpEnricher geoIpEnricher,
            UserAgentEnricher userAgentEnricher) {
        this.uploadService = uploadService;
        this.uploadRepository = uploadRepository;
        this.sourceRepository = sourceRepository;
        this.eventRepository = eventRepository;
        this.eventIndexer = eventIndexer;
        this.formatDetector = formatDetector;
        this.accessLogParser = accessLogParser;
        this.syslogParser = syslogParser;
        this.jsonLogParser = jsonLogParser;
        this.appConfig = appConfig;
        this.geoIpEnricher = geoIpEnricher;
        this.userAgentEnricher = userAgentEnricher;
    }

    @Override
    public void parse(LogIngestEvent event) {
        Objects.requireNonNull(event, "event");
        if (event.uploadId() == null) {
            throw new IllegalArgumentException("LogIngestEvent must contain an uploadId");
        }

        LogUpload upload =
                uploadRepository
                        .findByIdOptional(event.uploadId())
                        .orElseThrow(
                                () ->
                                        new NotFoundException(
                                                "no log upload with id " + event.uploadId()));

        Path filePath = Paths.get(event.storagePath());
        if (!Files.exists(filePath)) {
            throw new IllegalStateException("Uploaded log file not found at " + filePath);
        }

        LogFormat format = upload.getDetectedFormat();
        if (format == null || format == LogFormat.PLAIN) {
            format = formatDetector.detect(filePath, event.fileName());
        }
        if (format == null) {
            format = LogFormat.PLAIN;
        }

        LogSource source = resolveSource(upload, event);

        int batchSize = appConfig.search().bulkSize();
        long totalEvents = 0;
        List<LogEvent> batch = new ArrayList<>(batchSize);

        try (BufferedReader reader = Files.newBufferedReader(filePath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                NormalizedEvent normalized = parseLine(line, format);
                LogEvent logEvent = toLogEvent(normalized, source);
                if (logEvent.getExternalId() != null
                        && eventRepository.findByExternalId(logEvent.getExternalId()).isPresent()) {
                    continue;
                }
                batch.add(logEvent);
                if (batch.size() >= batchSize) {
                    persistAndIndexBatch(batch);
                    totalEvents += batch.size();
                    batch.clear();
                }
            }
            if (!batch.isEmpty()) {
                persistAndIndexBatch(batch);
                totalEvents += batch.size();
                batch.clear();
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read uploaded log file at " + filePath, e);
        }

        uploadService.markIngested(event.uploadId(), totalEvents);
        LOG.infof(
                "Ingested %d events for uploadId=%d from %s",
                totalEvents, event.uploadId(), event.fileName());
    }

    private void persistAndIndexBatch(List<LogEvent> batch) {
        if (batch.isEmpty()) {
            return;
        }
        QuarkusTransaction.requiringNew()
                .run(
                        () -> {
                            for (LogEvent logEvent : batch) {
                                eventRepository.persist(logEvent);
                            }
                            eventRepository.flush();
                            eventIndexer.indexAfterCommit(batch);
                        });
    }

    private LogSource resolveSource(LogUpload upload, LogIngestEvent event) {
        LogSource source = upload.getSource();
        if (source != null) {
            return source;
        }
        if (event.sourceId() != null) {
            source = sourceRepository.findByIdOptional(event.sourceId()).orElse(null);
            if (source != null) {
                return source;
            }
        }
        if (event.sourceName() != null && !event.sourceName().isBlank()) {
            source = sourceRepository.findByName(event.sourceName()).orElse(null);
            if (source != null) {
                return source;
            }
        }
        String name =
                (event.sourceName() != null && !event.sourceName().isBlank())
                        ? event.sourceName()
                        : "default";
        return QuarkusTransaction.requiringNew()
                .call(
                        () -> {
                            LogSource existing = sourceRepository.findByName(name).orElse(null);
                            if (existing != null) {
                                return existing;
                            }
                            LogSource newSource = new LogSource();
                            newSource.setName(name);
                            newSource.setType(resolveSourceType(event.sourceType()));
                            sourceRepository.persist(newSource);
                            return newSource;
                        });
    }

    private LogSourceType resolveSourceType(String sourceType) {
        if (sourceType != null) {
            try {
                return LogSourceType.valueOf(sourceType);
            } catch (IllegalArgumentException ignored) {
            }
        }
        return LogSourceType.APPLICATION;
    }

    NormalizedEvent parseLine(String line, LogFormat format) {
        Optional<NormalizedEvent> event = Optional.empty();
        if (format == LogFormat.JSON) {
            event = jsonLogParser.parse(line);
        } else if (format == LogFormat.SYSLOG) {
            event = syslogParser.parse(line);
        } else if (format == LogFormat.ACCESS_LOG) {
            event = accessLogParser.parse(line);
        }

        if (event.isEmpty() && format == LogFormat.PLAIN) {
            event = accessLogParser.parse(line);
            if (event.isEmpty()) {
                event = syslogParser.parse(line);
            }
            if (event.isEmpty()) {
                event = jsonLogParser.parse(line);
            }
        }

        return event.orElseGet(
                () ->
                        NormalizedEvent.builder(Instant.now(), LogFormat.PLAIN, line)
                                .message(line)
                                .build());
    }

    LogEvent toLogEvent(NormalizedEvent normalized, LogSource source) {
        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(
                normalized.timestamp() != null ? normalized.timestamp() : Instant.now());
        event.setSeverity(normalized.severity() != null ? normalized.severity() : Severity.INFO);
        String msg = normalized.message();
        if (msg == null || msg.isBlank()) {
            msg = normalized.raw();
        }
        event.setMessage(msg);
        event.setRaw(normalized.raw());

        Map<String, Object> payload = new LinkedHashMap<>();
        if (normalized.format() != null) {
            payload.put("format", normalized.format().name());
        }
        if (normalized.host() != null) {
            payload.put("host", normalized.host());
        }
        if (normalized.srcIp() != null) {
            payload.put("srcIp", normalized.srcIp());
        }
        if (normalized.srcPort() != null) {
            payload.put("srcPort", normalized.srcPort());
        }
        if (normalized.user() != null) {
            payload.put("user", normalized.user());
        }
        if (normalized.method() != null) {
            payload.put("method", normalized.method());
        }
        if (normalized.path() != null) {
            payload.put("path", normalized.path());
        }
        if (normalized.protocol() != null) {
            payload.put("protocol", normalized.protocol());
        }
        if (normalized.status() != null) {
            payload.put("status", normalized.status());
        }
        if (normalized.bytes() != null) {
            payload.put("bytes", normalized.bytes());
        }
        if (normalized.referrer() != null) {
            payload.put("referrer", normalized.referrer());
        }
        if (normalized.userAgent() != null) {
            payload.put("userAgent", normalized.userAgent());
        }
        if (normalized.attributes() != null && !normalized.attributes().isEmpty()) {
            payload.put("attributes", normalized.attributes());
            Object extId = normalized.attributes().get("externalId");
            if (extId == null) {
                extId = normalized.attributes().get("id");
            }
            if (extId != null) {
                event.setExternalId(String.valueOf(extId));
            }
        }
        applyGeo(payload, normalized.srcIp());
        applyUserAgent(payload, normalized.userAgent());
        event.setPayload(payload.isEmpty() ? null : payload);
        return event;
    }

    /**
     * Adds geo data for the event's source address. Absent values write no key at all: an empty
     * string or a "unknown" placeholder would be indexed and faceted as though it were a real
     * value.
     */
    private void applyGeo(Map<String, Object> payload, String srcIp) {
        if (srcIp == null) {
            return;
        }
        geoIpEnricher
                .lookup(srcIp)
                .ifPresent(
                        geo -> {
                            putIfPresent(payload, "geoCountryIso", geo.countryIso());
                            putIfPresent(payload, "geoCountryName", geo.countryName());
                            putIfPresent(payload, "geoCity", geo.city());
                            putIfPresent(payload, "geoAsn", geo.asn());
                            putIfPresent(payload, "geoAsOrg", geo.asOrg());
                            if (geo.latitude() != null && geo.longitude() != null) {
                                payload.put(
                                        "geoLocation",
                                        Map.of("lat", geo.latitude(), "lon", geo.longitude()));
                            }
                        });
    }

    /**
     * Adds the browser, operating system and bot classification of the event's User-Agent. Like
     * {@link #applyGeo}, a value the header does not carry writes no key; {@code uaBot} is written
     * whenever the header was classified at all, since {@code false} is a finding too.
     */
    private void applyUserAgent(Map<String, Object> payload, String userAgent) {
        if (userAgent == null) {
            return;
        }
        userAgentEnricher
                .classify(userAgent)
                .ifPresent(
                        ua -> {
                            putIfPresent(payload, "uaBrowser", ua.browser());
                            putIfPresent(payload, "uaBrowserVersion", ua.browserVersion());
                            putIfPresent(payload, "uaOs", ua.os());
                            putIfPresent(payload, "uaOsVersion", ua.osVersion());
                            putIfPresent(payload, "uaDeviceClass", ua.deviceClass());
                            putIfPresent(payload, "uaAgentClass", ua.agentClass());
                            payload.put("uaBot", ua.bot());
                        });
    }

    private static void putIfPresent(Map<String, Object> payload, String key, Object value) {
        if (value != null) {
            payload.put(key, value);
        }
    }
}
