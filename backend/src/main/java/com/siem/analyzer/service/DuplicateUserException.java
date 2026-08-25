package com.siem.analyzer.service;

/**
 * Thrown when an account cannot be written because another one already holds the same unique value.
 *
 * <p>Checked before the insert rather than left to the database constraint, so that the caller
 * learns which field collided. The constraints in {@code V2__users.sql} remain the authority — they
 * catch the concurrent case this check cannot.
 */
public class DuplicateUserException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String field;

    public DuplicateUserException(String field, String value) {
        super("a user with " + field + " '" + value + "' already exists");
        this.field = field;
    }

    /** Name of the field that collided, as the API spells it. */
    public String getField() {
        return field;
    }
}
