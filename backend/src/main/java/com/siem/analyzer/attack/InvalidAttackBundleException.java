package com.siem.analyzer.attack;

/**
 * A bundle that is not an ATT&CK Enterprise STIX bundle this application can store. Nothing is
 * written when one is refused, so the dataset already loaded stays as it was.
 */
public class InvalidAttackBundleException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidAttackBundleException(String message) {
        super(message);
    }

    public InvalidAttackBundleException(String message, Throwable cause) {
        super(message, cause);
    }
}
