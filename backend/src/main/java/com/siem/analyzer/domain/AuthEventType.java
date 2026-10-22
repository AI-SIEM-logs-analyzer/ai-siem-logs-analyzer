package com.siem.analyzer.domain;

public enum AuthEventType {
    LOGIN_SUCCESS,

    LOGIN_FAILURE,

    REFRESH,

    REFRESH_REUSE,

    LOGOUT,

    RATE_LIMITED
}
