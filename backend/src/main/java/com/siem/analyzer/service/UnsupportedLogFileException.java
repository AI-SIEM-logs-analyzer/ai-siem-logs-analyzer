package com.siem.analyzer.service;

/**
 * The uploaded file is not a log file this application accepts.
 *
 * <p>Deliberately one exception for all three type checks — extension, declared content type and
 * the sniff of the leading bytes. Telling a caller which of the three rejected the file would tell
 * anyone probing the endpoint how to dress a payload up to get past it, and a caller uploading a
 * genuine log file needs only to know what is accepted.
 */
public class UnsupportedLogFileException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UnsupportedLogFileException(String message) {
        super(message);
    }
}
