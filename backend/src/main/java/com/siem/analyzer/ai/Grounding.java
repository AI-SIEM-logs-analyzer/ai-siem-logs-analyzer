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

/**
 * Checks a model's answer against the alert it was given, so a summary that names what the alert
 * never held is refused rather than stored.
 *
 * <p>Two things are checked, both by plain text, with no second model involved:
 *
 * <ul>
 *   <li>every {@link AlertSummary#evidence() evidence} value, which the schema asks to be copied
 *       verbatim, has to appear in the alert;
 *   <li>every IP address the summary or the recommended action names has to be one of the addresses
 *       in the alert, whole: 10.0.0.70 does not pass because the alert holds 10.0.0.7. An address
 *       is where a made-up value does the most harm: "block 10.0.0.8" when the attacker was
 *       10.0.0.7 blocks the wrong host and lets the right one carry on. IPv6 letters may differ in
 *       case.
 * </ul>
 *
 * <p>The check is deliberately literal. It cannot tell whether a sentence draws the right
 * conclusion, only whether the concrete values it rests on are real; the prompt asks for the rest.
 */
public final class Grounding {

    /** Four dotted octets; a trailing full stop ends a sentence, not the address. */
    private static final Pattern IPV4 =
            Pattern.compile("(?<![\\d.])\\d{1,3}(?:\\.\\d{1,3}){3}(?!\\.?\\d)");

    /**
     * Colon-separated hex groups. Times such as {@code 10:00:05} have the same shape, so only a
     * candidate with {@code ::} or all eight groups counts as an address.
     */
    private static final Pattern IPV6 =
            Pattern.compile("(?<![\\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\\w:])");

    private static final Pattern HEX_DIGIT = Pattern.compile("[0-9A-Fa-f]");

    private Grounding() {}

    /**
     * The values in {@code answer} that {@code prompt} does not contain, in the order they were
     * found; empty when the answer is grounded.
     */
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

    /** The IPv4 and IPv6 addresses written in {@code text}, in order of appearance. */
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
