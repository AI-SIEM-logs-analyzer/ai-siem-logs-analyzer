package com.siem.analyzer.ai;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Grounding {

    private static final Pattern IPV4 =
            Pattern.compile("(?<![\\d.])\\d{1,3}(?:\\.\\d{1,3}){3}(?!\\.?\\d)");

    private static final Pattern IPV6 =
            Pattern.compile("(?<![\\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\\w:])");

    private static final Pattern HEX_DIGIT = Pattern.compile("[0-9A-Fa-f]");

    private Grounding() {}

    public static List<String> ungrounded(AlertSummary answer, AlertPrompt prompt) {
        Objects.requireNonNull(answer, "answer");
        Objects.requireNonNull(prompt, "prompt");
        Set<String> missing = new LinkedHashSet<>();
        if (answer.evidence() != null) {
            for (String quote : answer.evidence()) {
                if (!prompt.mentions(quote)) {
                    missing.add(quote);
                }
            }
        }
        Set<String> known = new HashSet<>();
        for (String address : addresses(prompt.values())) {
            known.add(address.toLowerCase(Locale.ROOT));
        }
        for (String text : new String[] {answer.summary(), answer.recommendedAction()}) {
            for (String address : addresses(text)) {
                if (!known.contains(address.toLowerCase(Locale.ROOT))) {
                    missing.add(address);
                }
            }
        }
        return List.copyOf(missing);
    }

    static List<String> addresses(String text) {
        List<String> found = new ArrayList<>();
        if (text == null) {
            return found;
        }
        Matcher ipv4 = IPV4.matcher(text);
        while (ipv4.find()) {
            found.add(ipv4.group());
        }
        Matcher ipv6 = IPV6.matcher(text);
        while (ipv6.find()) {
            String candidate = ipv6.group();
            boolean shaped =
                    candidate.contains("::")
                            || candidate.chars().filter(c -> c == ':').count() == 7;
            if (shaped && HEX_DIGIT.matcher(candidate).find()) {
                found.add(candidate);
            }
        }
        return found;
    }
}
