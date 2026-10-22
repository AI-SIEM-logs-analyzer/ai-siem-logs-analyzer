package com.siem.analyzer.detect.sigma;

import com.siem.analyzer.detect.RuleExpressionParser;
import com.siem.analyzer.detect.RuleSyntaxException;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public final class SigmaConverter {

    private static final String REGEX_META = "\\.[]{}()*+?^$|";

    private static final Set<String> SKIPPED_STATUSES = Set.of("deprecated", "unsupported");

    private static final Pattern ATTACK_TECHNIQUE_TAG =
            Pattern.compile("(?i)attack\\.(t\\d{4}(?:\\.\\d{3})?)");

    private static final int MAX_SLUG_LENGTH = 60;

    private final SigmaFieldMapping mapping;

    public SigmaConverter(SigmaFieldMapping mapping) {
        this.mapping = Objects.requireNonNull(mapping, "mapping");
    }

    public static SigmaConverter withDefaults() {
        return new SigmaConverter(SigmaFieldMapping.defaults());
    }

    public SigmaImport convert(String yaml) {
        List<SigmaRule> rules = new ArrayList<>();
        List<SigmaCorrelation> correlations = new ArrayList<>();
        List<SigmaImport.Skipped> skipped = new ArrayList<>();
        for (Map<String, Object> document : SigmaYaml.read(yaml)) {
            try {
                if (document.containsKey("action")) {
                    throw new SigmaException(
                            "Sigma 1 rule collections ('action') are not supported; split the"
                                    + " file into standalone rules");
                }
                if (document.containsKey("correlation")) {
                    correlations.add(SigmaCorrelation.from(document));
                } else {
                    rules.add(SigmaRule.from(document));
                }
            } catch (SigmaException e) {
                skipped.add(skippedDocument(document, e.getMessage()));
            }
        }

        Map<String, SigmaRule> byReference = new HashMap<>();
        for (SigmaRule rule : rules) {
            if (rule.meta().id() != null) {
                byReference.put(rule.meta().id(), rule);
            }
            if (rule.meta().name() != null) {
                byReference.put(rule.meta().name(), rule);
            }
        }
        Set<SigmaRule> correlatedOnly = new HashSet<>();
        for (SigmaCorrelation correlation : correlations) {
            if (!correlation.generate()) {
                correlation.rules().stream()
                        .map(byReference::get)
                        .filter(Objects::nonNull)
                        .forEach(correlatedOnly::add);
            }
        }

        List<ConvertedRule> converted = new ArrayList<>();
        Set<String> names = new HashSet<>();
        for (SigmaRule rule : rules) {
            if (correlatedOnly.contains(rule)) {
                continue;
            }
            collect(rule.meta(), () -> convert(rule), converted, names, skipped);
        }
        for (SigmaCorrelation correlation : correlations) {
            collect(
                    correlation.meta(),
                    () -> convert(correlation, byReference),
                    converted,
                    names,
                    skipped);
        }
        return new SigmaImport(converted, skipped);
    }

    private interface Conversion {
        ConvertedRule run();
    }

    private static void collect(
            SigmaRule.Meta meta,
            Conversion conversion,
            List<ConvertedRule> converted,
            Set<String> names,
            List<SigmaImport.Skipped> skipped) {
        try {
            if (meta.status() != null
                    && SKIPPED_STATUSES.contains(meta.status().toLowerCase(Locale.ROOT))) {
                throw new SigmaException("the rule's status is '" + meta.status() + "'");
            }
            ConvertedRule rule = conversion.run();
            if (!names.add(rule.name())) {
                throw new SigmaException(
                        "another rule in this import is also named " + rule.name());
            }
            converted.add(rule);
        } catch (SigmaException e) {
            skipped.add(new SigmaImport.Skipped(meta.title(), meta.id(), e.getMessage()));
        }
    }

    private static SigmaImport.Skipped skippedDocument(
            Map<String, Object> document, String reason) {
        Object title = document.get("title");
        Object id = document.get("id");
        return new SigmaImport.Skipped(
                title instanceof String text && !text.isBlank() ? text.strip() : "(untitled)",
                id instanceof String text ? text : null,
                reason);
    }

    private ConvertedRule convert(SigmaRule rule) {
        Map<String, Expr> searches = searches(rule);
        List<Expr> alternatives = new ArrayList<>();
        String window = null;
        for (String condition : rule.conditions()) {
            SigmaConditionParser.Parsed parsed = SigmaConditionParser.parse(condition, searches);
            if (parsed.aggregation() != null) {
                if (rule.conditions().size() > 1) {
                    throw new SigmaException(
                            "an aggregation is only supported in a rule's single condition");
                }
                window = window(parsed.aggregation(), rule.timeframe());
            }
            alternatives.add(parsed.condition());
        }
        return finish(rule.meta(), guarded(rule, Expr.or(alternatives)), window);
    }

    private Expr correlated(SigmaRule rule) {
        Map<String, Expr> searches = searches(rule);
        List<Expr> alternatives = new ArrayList<>();
        for (String condition : rule.conditions()) {
            SigmaConditionParser.Parsed parsed = SigmaConditionParser.parse(condition, searches);
            if (parsed.aggregation() != null) {
                throw new SigmaException(
                        "rule '"
                                + rule.meta().title()
                                + "' aggregates itself, so a correlation cannot count it");
            }
            alternatives.add(parsed.condition());
        }
        return guarded(rule, Expr.or(alternatives));
    }

    private Expr guarded(SigmaRule rule, Expr condition) {
        List<Expr> all = new ArrayList<>();
        mapping.guards(rule.logsource()).forEach(guard -> all.add(Expr.leaf(guard)));
        all.add(condition);
        return Expr.and(all);
    }

    private Map<String, Expr> searches(SigmaRule rule) {
        Map<String, Expr> searches = new LinkedHashMap<>();
        rule.searches().forEach((name, definition) -> searches.put(name, search(name, definition)));
        return searches;
    }

    private String window(SigmaConditionParser.Aggregation aggregation, String timeframe) {
        if (timeframe == null) {
            throw new SigmaException("the aggregation has no 'timeframe' to count within");
        }
        String measure =
                switch (aggregation.function()) {
                    case "count" ->
                            aggregation.field() == null
                                    ? "count"
                                    : "distinct(" + mappedField(aggregation.field()) + ")";
                    case "sum" -> "sum(" + mappedField(required(aggregation.field())) + ")";
                    default ->
                            throw new SigmaException(
                                    "the '"
                                            + aggregation.function()
                                            + "' aggregation is not supported");
                };
        List<String> groupBy =
                aggregation.groupBy() == null ? List.of() : List.of(aggregation.groupBy());
        return window(
                measure,
                groupBy,
                timeframe,
                rising(aggregation.operator()),
                aggregation.threshold());
    }

    private static String required(String field) {
        if (field == null) {
            throw new SigmaException("sum() needs a field");
        }
        return field;
    }

    private static String rising(String operator) {
        return switch (operator) {
            case ">", "gt" -> ">";
            case ">=", "gte" -> ">=";
            default ->
                    throw new SigmaException(
                            "threshold '"
                                    + operator
                                    + "' is not supported; the engine fires when a value rises"
                                    + " past > or >=");
        };
    }

    private String window(
            String measure,
            List<String> groupBy,
            String timespan,
            String operator,
            BigDecimal threshold) {
        StringBuilder window = new StringBuilder(measure);
        if (!groupBy.isEmpty()) {
            window.append(" by ")
                    .append(String.join(", ", groupBy.stream().map(this::mappedField).toList()));
        }
        if (threshold.signum() < 0) {
            throw new SigmaException("the threshold must not be negative");
        }
        return window.append(" within ")
                .append(duration(timespan))
                .append(' ')
                .append(operator)
                .append(' ')
                .append(threshold.toPlainString())
                .toString();
    }

    private static String duration(String timespan) {
        if (timespan == null || !timespan.matches("[1-9]\\d{0,8}[smhd]")) {
            throw new SigmaException(
                    "time span '"
                            + timespan
                            + "' is not supported; use a whole number of s, m, h or d");
        }
        return timespan;
    }

    private String mappedField(String sigmaField) {
        return mapping.field(sigmaField);
    }

    private ConvertedRule convert(
            SigmaCorrelation correlation, Map<String, SigmaRule> byReference) {
        List<Expr> correlated = new ArrayList<>();
        for (String reference : correlation.rules()) {
            SigmaRule rule = byReference.get(reference);
            if (rule == null) {
                throw new SigmaException(
                        "the correlation refers to rule '"
                                + reference
                                + "', which is not in this import");
            }
            correlated.add(correlated(rule));
        }
        String measure =
                switch (correlation.type()) {
                    case "event_count" -> "count";
                    case "value_count" -> "distinct(" + mappedField(field(correlation)) + ")";
                    case "value_sum" -> "sum(" + mappedField(field(correlation)) + ")";
                    default ->
                            throw new SigmaException(
                                    "correlation type '"
                                            + correlation.type()
                                            + "' is not supported");
                };
        String window =
                window(
                        measure,
                        correlation.groupBy(),
                        correlation.timespan(),
                        rising(correlation.thresholdOperator()),
                        correlation.threshold());
        return finish(correlation.meta(), Expr.or(correlated), window);
    }

    private static String field(SigmaCorrelation correlation) {
        if (correlation.field() == null) {
            throw new SigmaException("a " + correlation.type() + " correlation needs a 'field'");
        }
        return correlation.field();
    }

    private static ConvertedRule finish(SigmaRule.Meta meta, Expr condition, String window) {
        String expression = condition.render() + (window == null ? "" : " | " + window);
        try {
            RuleExpressionParser.parse(expression);
        } catch (RuleSyntaxException e) {
            throw new SigmaException("the converted rule does not parse: " + e.getMessage());
        }
        return new ConvertedRule(
                name(meta),
                meta.title(),
                meta.id(),
                severity(meta.level()),
                description(meta),
                expression,
                attackTechniques(meta.tags()));
    }

    static Set<String> attackTechniques(List<String> tags) {
        Set<String> ids = new TreeSet<>();
        for (String tag : tags) {
            Matcher matcher = ATTACK_TECHNIQUE_TAG.matcher(tag.strip());
            if (matcher.matches()) {
                ids.add(matcher.group(1).toUpperCase(Locale.ROOT));
            }
        }
        return ids;
    }

    static String name(SigmaRule.Meta meta) {
        String slug =
                meta.title()
                        .toLowerCase(Locale.ROOT)
                        .replaceAll("[^a-z0-9]+", "-")
                        .replaceAll("^-|-$", "");
        if (slug.length() > MAX_SLUG_LENGTH) {
            slug = slug.substring(0, MAX_SLUG_LENGTH).replaceAll("-$", "");
        }
        StringBuilder name = new StringBuilder("sigma");
        if (!slug.isEmpty()) {
            name.append('-').append(slug);
        }
        if (meta.id() != null) {
            String id = meta.id().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
            if (!id.isEmpty()) {
                name.append('-').append(id, 0, Math.min(8, id.length()));
            }
        }
        return name.toString();
    }

    static Severity severity(String level) {
        if (level == null) {
            return Severity.WARNING;
        }
        return switch (level.toLowerCase(Locale.ROOT)) {
            case "informational", "low" -> Severity.INFO;
            case "medium" -> Severity.WARNING;
            case "high" -> Severity.ERROR;
            case "critical" -> Severity.CRITICAL;
            default -> throw new SigmaException("unknown level '" + level + "'");
        };
    }

    private static String description(SigmaRule.Meta meta) {
        StringBuilder description =
                new StringBuilder(meta.description() == null ? meta.title() : meta.description());
        description.append("\n\nImported from Sigma rule \"").append(meta.title()).append('"');
        if (meta.id() != null) {
            description.append(" (").append(meta.id()).append(')');
        }
        if (meta.author() != null) {
            description.append(" by ").append(meta.author());
        }
        description.append('.');
        if (!meta.falsepositives().isEmpty()) {
            description
                    .append("\nFalse positives: ")
                    .append(String.join("; ", meta.falsepositives()));
        }
        if (!meta.references().isEmpty()) {
            description.append("\nReferences: ").append(String.join(" ", meta.references()));
        }
        return description.toString();
    }

    private Expr search(String identifier, Object definition) {
        if (definition instanceof Map<?, ?> map) {
            return fields(identifier, SigmaYaml.stringKeys(map));
        }
        if (definition instanceof List<?> list && !list.isEmpty()) {
            List<Expr> alternatives = new ArrayList<>();
            List<Object> keywords = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    alternatives.add(fields(identifier, SigmaYaml.stringKeys(map)));
                } else if (isScalar(item)) {
                    keywords.add(item);
                } else {
                    throw new SigmaException(
                            "search identifier '" + identifier + "' holds a nested list");
                }
            }
            if (!keywords.isEmpty()) {
                alternatives.add(item(identifier, "", keywords));
            }
            return Expr.or(alternatives);
        }
        if (isScalar(definition)) {
            return item(identifier, "", List.of(definition));
        }
        throw new SigmaException("search identifier '" + identifier + "' is empty");
    }

    private Expr fields(String identifier, Map<String, Object> fields) {
        if (fields.isEmpty()) {
            throw new SigmaException("search identifier '" + identifier + "' is empty");
        }
        List<Expr> all = new ArrayList<>();
        fields.forEach(
                (key, value) -> {
                    List<Object> values;
                    if (value instanceof List<?> list) {
                        values = new ArrayList<>(list);
                    } else {
                        values = new ArrayList<>();
                        values.add(value);
                    }
                    all.add(item(identifier, key, values));
                });
        return Expr.and(all);
    }

    private Expr item(String identifier, String key, List<Object> values) {
        if (values.isEmpty()) {
            throw new SigmaException("'" + key + "' in '" + identifier + "' has no values");
        }
        String[] parts = key.split("\\|", -1);
        Modifiers modifiers = Modifiers.parse(parts, key);
        boolean keyword = parts[0].isEmpty();
        String field = keyword ? "raw" : mapping.field(parts[0]);

        if (!keyword && !modifiers.all() && values.size() > 1 && modifiers.isPlain()) {
            String in = in(field, values);
            if (in != null) {
                return Expr.leaf(in);
            }
        }
        List<Expr> matches = new ArrayList<>(values.size());
        for (Object value : values) {
            if (!isScalar(value) && value != null) {
                throw new SigmaException("'" + key + "' holds a nested mapping or list");
            }
            matches.add(value(field, value, modifiers, keyword, key));
        }
        return modifiers.all() ? Expr.and(matches) : Expr.or(matches);
    }

    private static String in(String field, List<Object> values) {
        List<String> literals = new ArrayList<>();
        for (Object value : values) {
            if (value instanceof Number) {
                String number = number(value);
                if (number == null) {
                    return null;
                }
                literals.add(number);
            } else if (value instanceof String text
                    && !text.isEmpty()
                    && SigmaString.parse(text).isLiteral()) {
                literals.add(quote(SigmaString.parse(text).literal()));
            } else {
                return null;
            }
        }
        return field + " in (" + String.join(", ", literals) + ")";
    }

    private Expr value(
            String field, Object value, Modifiers modifiers, boolean keyword, String key) {
        if (modifiers.exists()) {
            if (!(value instanceof Boolean present)) {
                throw new SigmaException("'" + key + "' needs true or false");
            }
            Expr exists = Expr.leaf(field + " exists");
            return present ? exists : Expr.not(exists);
        }
        if (value == null) {
            if (!modifiers.isPlain() || keyword) {
                throw new SigmaException("'" + key + "' compares null with a modifier");
            }
            return Expr.not(Expr.leaf(field + " exists"));
        }
        if (modifiers.comparison() != null) {
            String number = value instanceof Number ? number(value) : null;
            if (number == null) {
                throw new SigmaException("'" + key + "' needs a number");
            }
            return Expr.leaf(field + " " + modifiers.comparison() + " " + number);
        }
        if (modifiers.regex()) {
            if (!(value instanceof String regex)) {
                throw new SigmaException("'" + key + "' needs a regular expression as text");
            }
            String pattern = modifiers.regexFlags() + regex;
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new SigmaException(
                        "'" + key + "' has an invalid regular expression: " + e.getDescription());
            }
            return Expr.leaf(field + " matches " + quote(pattern));
        }
        if (modifiers.isPlain() && !keyword) {
            if (value instanceof Number) {
                String number = number(value);
                if (number != null) {
                    return Expr.leaf(field + " == " + number);
                }
            }
            if (value instanceof Boolean) {
                return Expr.leaf(field + " == " + quote(value.toString()));
            }
        }

        String text = value instanceof Number ? number(value) : String.valueOf(value);
        if (text == null) {
            throw new SigmaException("'" + key + "' holds a number the engine cannot represent");
        }
        Match match = keyword ? Match.CONTAINS : modifiers.match();
        if (modifiers.base64() != Base64Mode.NONE) {
            SigmaString encoded = SigmaString.parse(text);
            if (!encoded.isLiteral()) {
                throw new SigmaException("'" + key + "' combines base64 with wildcards");
            }
            List<Expr> variants = new ArrayList<>();
            for (String variant : modifiers.base64().encode(encoded.literal())) {
                variants.add(
                        matchString(field, SigmaString.literal(variant), match, modifiers.cased()));
            }
            return Expr.or(variants);
        }
        return matchString(field, SigmaString.parse(text), match, modifiers.cased());
    }

    private static Expr matchString(String field, SigmaString value, Match match, boolean cased) {
        SigmaString pattern = value.anchoredFor(match);
        boolean leading = pattern.startsWithAny();
        boolean trailing = pattern.endsWithAny();
        SigmaString middle = pattern.trimAny();
        if (middle.isEmpty()) {
            if (leading || trailing) {
                return Expr.leaf(field + " exists");
            }
            return Expr.or(
                    List.of(Expr.not(Expr.leaf(field + " exists")), Expr.leaf(field + " == \"\"")));
        }
        if (middle.isLiteral() && !cased) {
            String literal = quote(middle.literal());
            if (leading && trailing) {
                return Expr.leaf(field + " contains " + literal);
            }
            if (trailing) {
                return Expr.leaf(field + " startswith " + literal);
            }
            if (leading) {
                return Expr.leaf(field + " endswith " + literal);
            }
            return Expr.leaf(field + " == " + literal);
        }
        StringBuilder regex = new StringBuilder();
        if (!leading) {
            regex.append('^');
        }
        regex.append(middle.toRegex());
        if (!trailing) {
            regex.append('$');
        }
        String flags = (cased ? "" : "i") + (middle.isLiteral() ? "" : "s");
        String prefix = flags.isEmpty() ? "" : "(?" + flags + ")";
        return Expr.leaf(field + " matches " + quote(prefix + regex));
    }

    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    static BigDecimal decimal(Object value) {
        if (!(value instanceof Number)) {
            return null;
        }
        try {
            return new BigDecimal(value.toString());
        } catch (NumberFormatException notFinite) {
            return null;
        }
    }

    private static String number(Object value) {
        BigDecimal decimal = decimal(value);
        return decimal == null ? null : decimal.toPlainString();
    }

    static String quote(String text) {
        StringBuilder quoted = new StringBuilder(text.length() + 2).append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '\\' -> {
                    char after = i + 1 < text.length() ? text.charAt(i + 1) : '\\';
                    quoted.append("nt\\\"'".indexOf(after) >= 0 ? "\\\\" : "\\");
                }
                case '"' -> quoted.append("\\\"");
                case '\n' -> quoted.append("\\n");
                case '\t' -> quoted.append("\\t");
                default -> quoted.append(c);
            }
        }
        return quoted.append('"').toString();
    }

    static String regexLiteral(String text) {
        StringBuilder escaped = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (REGEX_META.indexOf(c) >= 0) {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }

    enum Match {
        EQUALS,
        CONTAINS,
        STARTS_WITH,
        ENDS_WITH
    }

    enum Base64Mode {
        NONE,
        PLAIN,
        OFFSET;

        List<String> encode(String value) {
            Base64.Encoder encoder = Base64.getEncoder();
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (this == PLAIN) {
                return List.of(encoder.encodeToString(bytes));
            }
            int[] starts = {0, 2, 3};
            int[] ends = {0, 3, 2};
            List<String> variants = new ArrayList<>(3);
            for (int shift = 0; shift < 3; shift++) {
                byte[] shifted = new byte[bytes.length + shift];
                System.arraycopy(bytes, 0, shifted, shift, bytes.length);
                String encoded = encoder.encodeToString(shifted);
                int end = encoded.length() - ends[(bytes.length + shift) % 3];
                if (end > starts[shift]) {
                    variants.add(encoded.substring(starts[shift], end));
                }
            }
            if (variants.isEmpty()) {
                throw new SigmaException("'" + value + "' is too short for base64offset");
            }
            return variants;
        }
    }

    record Modifiers(
            Match match,
            boolean all,
            boolean regex,
            String regexFlags,
            boolean cased,
            boolean exists,
            String comparison,
            Base64Mode base64) {

        boolean isPlain() {
            return match == Match.EQUALS
                    && !regex
                    && !cased
                    && !exists
                    && comparison == null
                    && base64 == Base64Mode.NONE;
        }

        static Modifiers parse(String[] parts, String key) {
            Match match = Match.EQUALS;
            boolean all = false;
            boolean regex = false;
            StringBuilder flags = new StringBuilder();
            boolean cased = false;
            boolean exists = false;
            String comparison = null;
            Base64Mode base64 = Base64Mode.NONE;
            for (int i = 1; i < parts.length; i++) {
                String modifier = parts[i].toLowerCase(Locale.ROOT);
                switch (modifier) {
                    case "contains", "startswith", "endswith" -> {
                        if (match != Match.EQUALS) {
                            throw new SigmaException("'" + key + "' has two match modifiers");
                        }
                        match =
                                switch (modifier) {
                                    case "contains" -> Match.CONTAINS;
                                    case "startswith" -> Match.STARTS_WITH;
                                    default -> Match.ENDS_WITH;
                                };
                    }
                    case "all" -> all = true;
                    case "re" -> regex = true;
                    case "i", "m", "s" -> flags.append(modifier);
                    case "cased" -> cased = true;
                    case "exists" -> exists = true;
                    case "lt" -> comparison = "<";
                    case "lte" -> comparison = "<=";
                    case "gt" -> comparison = ">";
                    case "gte" -> comparison = ">=";
                    case "base64" -> base64 = Base64Mode.PLAIN;
                    case "base64offset" -> base64 = Base64Mode.OFFSET;
                    case "cidr",
                                    "windash",
                                    "fieldref",
                                    "expand",
                                    "wide",
                                    "utf16",
                                    "utf16le",
                                    "utf16be" ->
                            throw new SigmaException(
                                    "the '" + modifier + "' modifier is not supported");
                    default -> throw new SigmaException("unknown modifier '" + modifier + "'");
                }
            }
            if (!flags.isEmpty() && !regex) {
                throw new SigmaException("'" + key + "' has regex flags without 're'");
            }
            if (regex && (match != Match.EQUALS || cased || base64 != Base64Mode.NONE)) {
                throw new SigmaException("'" + key + "' combines 're' with another match modifier");
            }
            boolean special = exists || comparison != null;
            if (special && (match != Match.EQUALS || regex || cased || base64 != Base64Mode.NONE)) {
                throw new SigmaException("'" + key + "' combines incompatible modifiers");
            }
            return new Modifiers(
                    match,
                    all,
                    regex,
                    flags.isEmpty() ? "" : "(?" + flags + ")",
                    cased,
                    exists,
                    comparison,
                    base64);
        }
    }
}
