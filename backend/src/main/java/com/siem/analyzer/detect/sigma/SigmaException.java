package com.siem.analyzer.detect.sigma;

/**
 * A Sigma rule that cannot be imported: it is malformed, or it uses something the rule engine
 * cannot express. The message says which, in terms of the Sigma rule.
 */
public final class SigmaException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    public SigmaException(String message) {
        super(message);
    }
}
