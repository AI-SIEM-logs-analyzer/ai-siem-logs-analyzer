package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;
import org.jboss.resteasy.reactive.multipart.FileUpload;

/**
 * Persists uploaded log files to the configured storage directory and computes their SHA-256
 * checksum.
 */
@ApplicationScoped
public class LogStorageService {

    private final Path storageDir;

    @Inject
    public LogStorageService(AppConfig config) {
        this(Paths.get(config.storage().uploadDir()));
    }

    public LogStorageService(Path storageDir) {
        this.storageDir = storageDir;
        try {
            Files.createDirectories(storageDir);
        } catch (IOException e) {
            throw new IllegalStateException("Could not create storage directory: " + storageDir, e);
        }
    }

    /** Stores an uploaded file from a {@link FileUpload}. */
    public StoredFile store(FileUpload fileUpload) {
        if (fileUpload == null || fileUpload.filePath() == null) {
            throw new IllegalArgumentException("FileUpload is null or has no file path");
        }
        Path sourcePath = fileUpload.filePath();
        if (!Files.exists(sourcePath)) {
            throw new IllegalArgumentException("Uploaded file does not exist at " + sourcePath);
        }
        try {
            long size = Files.size(sourcePath);
            if (size == 0) {
                throw new IllegalArgumentException("Uploaded file is empty");
            }
            try (InputStream in = Files.newInputStream(sourcePath)) {
                return store(in, fileUpload.fileName(), fileUpload.contentType());
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read uploaded file", e);
        }
    }

    /** Stores an uploaded file from an {@link InputStream}. */
    public StoredFile store(InputStream in, String originalFileName, String contentType) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String safeName = sanitizeFileName(originalFileName);
            String storedFileName = UUID.randomUUID() + "_" + safeName;
            Path targetPath = storageDir.resolve(storedFileName);

            long actualSize;
            try (DigestInputStream digestIn = new DigestInputStream(in, digest)) {
                actualSize = Files.copy(digestIn, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }

            if (actualSize == 0) {
                Files.deleteIfExists(targetPath);
                throw new IllegalArgumentException("Uploaded file is empty");
            }

            String checksum = HexFormat.of().formatHex(digest.digest());
            return new StoredFile(
                    targetPath.toAbsolutePath().toString(),
                    actualSize,
                    checksum,
                    originalFileName,
                    contentType);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to store uploaded file", e);
        }
    }

    private static String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return "uploaded.log";
        }
        Path p = Paths.get(fileName);
        Path fn = p.getFileName();
        String name = fn != null ? fn.toString() : "uploaded.log";
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    /** Record describing a stored file and its metadata. */
    public record StoredFile(
            String storagePath,
            long size,
            String checksum,
            String originalFileName,
            String contentType) {}
}
