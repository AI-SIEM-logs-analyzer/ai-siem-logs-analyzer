package com.siem.analyzer.parse;

import java.time.Clock;
import java.time.ZoneOffset;

/** Parsers built without CDI, for tests outside this package. */
public final class ParserFixtures {

    private ParserFixtures() {}

    /**
     * A JSON parser with the default field mapping, reading offset-less timestamps as UTC.
     *
     * @param clock stamps a line that carries no usable timestamp
     */
    public static JsonLogParser json(Clock clock) {
        return new JsonLogParser(JsonFieldMapping.defaults(), clock, ZoneOffset.UTC);
    }
}
