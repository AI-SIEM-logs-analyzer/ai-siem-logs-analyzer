package com.siem.analyzer.service;

/**
 * Authentication was refused.
 *
 * <p>One exception for every reason — wrong password, unknown username, disabled account, spent
 * refresh token — because the caller must not be able to tell them apart. The reason is recorded in
 * the audit trail instead, where it is useful and not disclosed.
 */
public class InvalidCredentialsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
