package com.siem.analyzer.parse;

import java.time.Clock;
import java.time.ZoneOffset;

public final class ParserFixtures {

    private ParserFixtures() {}

    public static JsonLogParser json(Clock clock) {
        return new JsonLogParser(JsonFieldMapping.defaults(), clock, ZoneOffset.UTC);
    }
}
