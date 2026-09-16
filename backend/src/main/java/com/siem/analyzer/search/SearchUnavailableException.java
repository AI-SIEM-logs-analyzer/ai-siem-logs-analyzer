package com.siem.analyzer.search;

/**
 * The search engine could not be reached, or refused the request.
 *
 * <p>Distinct from an empty result on purpose: "nothing matched" and "we could not look" are
 * different answers, and a caller that conflates them reports a clean board during an outage. The
 * REST layer maps this to 503.
 */
public class SearchUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SearchUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }

    public SearchUnavailableException(String message) {
        super(message);
    }
}
