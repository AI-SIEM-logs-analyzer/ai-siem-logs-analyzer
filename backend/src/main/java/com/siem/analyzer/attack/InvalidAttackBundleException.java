package com.siem.analyzer.attack;

public class InvalidAttackBundleException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidAttackBundleException(String message) {
        super(message);
    }

    public InvalidAttackBundleException(String message, Throwable cause) {
        super(message, cause);
    }
}
