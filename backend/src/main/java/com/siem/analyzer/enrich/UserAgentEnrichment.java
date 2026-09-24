package com.siem.analyzer.enrich;

/**
 * What a User-Agent header says about the client that sent it. Every field is optional: a header
 * names a browser without an operating system, or a robot without a version, as often as not. A
 * {@code null} field means the header did not say, and the caller writes nothing for it rather than
 * an "Unknown" that would be faceted as though it were a real value.
 *
 * @param browser the agent's name, such as {@code Chrome}, {@code Firefox}, {@code Googlebot} or
 *     {@code Curl}; for a robot or a tool this is the robot or the tool, not a browser
 * @param browserVersion the agent's full version, as the header spells it
 * @param os the operating system's name, such as {@code Windows NT}, {@code Mac OS}, {@code
 *     Android}
 * @param osVersion the operating system's version, as the header spells it
 * @param deviceClass the kind of device: {@code Desktop}, {@code Phone}, {@code Tablet}, {@code
 *     Robot}, {@code Hacker}, ...
 * @param agentClass the kind of agent: {@code Browser}, {@code Robot} (crawlers, but also
 *     command-line tools, HTTP libraries and headless browsers), {@code Hacker}, ...
 * @param bot whether the agent is automated rather than a person at a browser. A {@code Hacker}
 *     header (an attack payload, a scanner's signature, or a value no real client sends) counts as
 *     a bot, and leaves the browser and operating system fields empty
 */
public record UserAgentEnrichment(
        String browser,
        String browserVersion,
        String os,
        String osVersion,
        String deviceClass,
        String agentClass,
        boolean bot) {}
