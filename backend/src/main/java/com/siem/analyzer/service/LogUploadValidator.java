package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@ApplicationScoped
public class LogUploadValidator {

    private static final byte[][] BINARY_MAGIC = {
        {0x1f, (byte) 0x8b},
        {0x50, 0x4b, 0x03, 0x04},
        {0x7f, 0x45, 0x4c, 0x46},
        {0x4d, 0x5a},
        {(byte) 0xfd, 0x37, 0x7a, 0x58, 0x5a},
        {0x42, 0x5a, 0x68},
        {0x28, (byte) 0xb5, 0x2f, (byte) 0xfd},
        {0x25, 0x50, 0x44, 0x46},
    };

    private final long maxSizeBytes;
    private final Set<String> allowedExtensions;
    private final Set<String> allowedContentTypes;
    private final int sniffBytes;

    @Inject
    public LogUploadValidator(AppConfig config) {
        this(
                config.upload().maxFileSizeBytes(),
                config.upload().allowedExtensions(),
                config.upload().allowedContentTypes(),
                config.upload().sniffBytes());
    }

    public LogUploadValidator(
            long maxSizeBytes,
            List<String> allowedExtensions,
            List<String> allowedContentTypes,
            int sniffBytes) {
        this.maxSizeBytes = maxSizeBytes;
        this.allowedExtensions = lowercased(allowedExtensions);
        this.allowedContentTypes = lowercased(allowedContentTypes);
        this.sniffBytes = sniffBytes;
    }

    public void validate(Path filePath, String fileName, String contentType) {
        if (filePath == null || !Files.exists(filePath)) {
            throw new BadRequestException("file part is required");
        }

        long size;
        try {
            size = Files.size(filePath);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read uploaded file", e);
        }
        if (size == 0) {
            throw new BadRequestException("uploaded file is empty");
        }
        if (size > maxSizeBytes) {
            throw new PayloadTooLargeException(size, maxSizeBytes);
        }

        String extension = extensionOf(fileName);
        if (!allowedExtensions.contains(extension)) {
            throw new UnsupportedLogFileException(
                    "file extension is not accepted, allowed: " + allowedExtensions);
        }

        String baseType = baseContentType(contentType);
        if (!allowedContentTypes.contains(baseType)) {
            throw new UnsupportedLogFileException(
                    "content type is not accepted, allowed: " + allowedContentTypes);
        }

        sniff(filePath);
    }

    private void sniff(Path filePath) {
        byte[] head = new byte[sniffBytes];
        int read;
        try (InputStream in = Files.newInputStream(filePath)) {
            read = in.readNBytes(head, 0, sniffBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read uploaded file", e);
        }

        for (byte[] magic : BINARY_MAGIC) {
            if (startsWith(head, read, magic)) {
                throw new UnsupportedLogFileException("uploaded file is not a text log file");
            }
        }

        for (int i = 0; i < read; i++) {
            if (isBinaryByte(head[i])) {
                throw new UnsupportedLogFileException("uploaded file is not a text log file");
            }
        }
    }

    private static boolean isBinaryByte(byte b) {
        if (b == 0x09 || b == 0x0a || b == 0x0c || b == 0x0d) {
            return false;
        }

        return (b >= 0 && b < 0x20) || b == 0x7f;
    }

    private static boolean startsWith(byte[] head, int length, byte[] prefix) {
        if (length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (head[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static String extensionOf(String fileName) {
        if (fileName == null) {
            return "";
        }
        Path name = Path.of(fileName).getFileName();
        String base = name != null ? name.toString() : fileName;
        int dot = base.lastIndexOf('.');
        if (dot < 0 || dot == base.length() - 1) {
            return "";
        }
        return base.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    private static String baseContentType(String contentType) {
        if (contentType == null) {
            return "";
        }
        int semicolon = contentType.indexOf(';');
        String base = semicolon < 0 ? contentType : contentType.substring(0, semicolon);
        return base.trim().toLowerCase(Locale.ROOT);
    }

    private static Set<String> lowercased(List<String> values) {
        return values.stream()
                .map(v -> v.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }
}
