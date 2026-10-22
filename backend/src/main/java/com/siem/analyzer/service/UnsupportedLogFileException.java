package com.siem.analyzer.service;

public class UnsupportedLogFileException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UnsupportedLogFileException(String message) {
        super(message);
    }
}
