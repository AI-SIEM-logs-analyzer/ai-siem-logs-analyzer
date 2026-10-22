package com.siem.analyzer.security;

public record RefreshRecord(long userId, String family, long issuedAtEpochSecond) {}
