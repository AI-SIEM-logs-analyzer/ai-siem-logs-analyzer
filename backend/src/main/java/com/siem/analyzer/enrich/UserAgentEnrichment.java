package com.siem.analyzer.enrich;

public record UserAgentEnrichment(
        String browser,
        String browserVersion,
        String os,
        String osVersion,
        String deviceClass,
        String agentClass,
        boolean bot) {}
