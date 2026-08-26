package com.siem.analyzer.domain;

/**
 * What happened during an authentication attempt.
 *
 * <p>Constant names are the stored values, listed by the {@code ck_auth_event_type} constraint.
 */
public enum AuthEventType {

    /** Credentials accepted and a token pair issued. */
    LOGIN_SUCCESS,

    /** Credentials refused: wrong password, unknown username, or a disabled account. */
    LOGIN_FAILURE,

    /** A refresh token was exchanged, or an unknown one was presented. */
    REFRESH,

    /** A refresh token was presented twice — the sessions of that account were revoked. */
    REFRESH_REUSE,

    /** A session was ended deliberately. */
    LOGOUT,

    /** An attempt was turned away without checking the password, for making too many. */
    RATE_LIMITED
}
