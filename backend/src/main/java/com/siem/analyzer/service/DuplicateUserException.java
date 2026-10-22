package com.siem.analyzer.service;

public class DuplicateUserException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String field;

    public DuplicateUserException(String field, String value) {
        super("a user with " + field + " '" + value + "' already exists");
        this.field = field;
    }

    public String getField() {
        return field;
    }
}
