package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;

public interface LogFileParser {

    void parse(LogIngestEvent event);
}
