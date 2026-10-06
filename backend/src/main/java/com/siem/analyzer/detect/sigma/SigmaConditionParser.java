package com.siem.analyzer.detect.sigma;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses a Sigma {@code condition} over search identifiers that are already converted.
 *
 * <pre>
 * condition   := or ( '|' aggregation )?
 * or          := and ( 'or' and )*
 * and         := unary ( 'and' unary )*
 * unary       := 'not' unary | '(' or ')' | quantifier | IDENTIFIER
 * quantifier  := ( '1' | 'any' | 'all' ) 'of' ( 'them' | PATTERN )
 * aggregation := FUNCTION '(' field? ')' ( 'by' field )? OPERATOR NUMBER
 * </pre>
 *
 * <p>Keywords are case-insensitive. {@code them} is every search identifier not starting with an
 * underscore; a {@code PATTERN} is an identifier with {@code *} wildcards. The aggregation is Sigma
 * 1's, kept for the many rules still written that way; Sigma 2 moves it into correlation rules. Its
 * field names are returned as written, for the caller to map.
 */
final class SigmaConditionParser {

    private static final Pattern TOKEN = Pattern.compile("[()]|[^\\s()]+");

    private static final Pattern AGGREGATION =
            Pattern.compile(
                    "\\s*+(\\w++)\\s*+\\(\\s*+([^\\s()]*+)\\s*+\\)"
                            + "(?:\\s++by\\s++([^\\s<>=]++))?"
                            + "\\s*+(<=|>=|==|=|<|>)\\s*+(-?\\d++(?:\\.\\d++)?)\\s*+",
                    Pattern.CASE_INSENSITIVE);

    private final String source;
    private final Map<String, Expr> searches;
    private final List<String> tokens = new ArrayList<>();
    private int next;

    /**
     * A Sigma 1 aggregation, after the {@code |}.
     *
     * @param function {@code count}, {@code sum}, … lower-cased
     * @param field the function's argument; {@code null} for {@code count()}
     * @param groupBy the {@code by} field; {@code null} when absent
     * @param operator as written: {@code >}, {@code >=}, …
     */
    record Aggregation(
            String function, String field, String groupBy, String operator, BigDecimal threshold) {}

    /** A parsed condition and its aggregation, {@code null} when there is none. */
    record Parsed(Expr condition, Aggregation aggregation) {}

    private SigmaConditionParser(String source, Map<String, Expr> searches) {
        this.source = source;
        this.searches = searches;
        Matcher matcher = TOKEN.matcher(source);
        while (matcher.find()) {
            tokens.add(matcher.group());
        }
    }

    /**
     * Parses one condition.
     *
     * @param searches the rule's search identifiers, converted, in file order
     * @throws SigmaException the condition is malformed or names an identifier that is not defined
     */
    static Parsed parse(String condition, Map<String, Expr> searches) {
        int bar = condition.indexOf('|');
        String head = bar < 0 ? condition : condition.substring(0, bar);
        SigmaConditionParser parser = new SigmaConditionParser(head, searches);
        Expr expr = parser.or();
        if (parser.next < parser.tokens.size()) {
            throw parser.error("unexpected '" + parser.tokens.get(parser.next) + "'");
        }
        return new Parsed(expr, bar < 0 ? null : aggregation(condition.substring(bar + 1)));
    }

    private Expr or() {
        List<Expr> operands = new ArrayList<>(List.of(and()));
        while (accept("or")) {
            operands.add(and());
        }
        return Expr.or(operands);
    }

    private Expr and() {
        List<Expr> operands = new ArrayList<>(List.of(unary()));
        while (accept("and")) {
            operands.add(unary());
        }
        return Expr.and(operands);
    }

    private Expr unary() {
        if (next >= tokens.size()) {
            throw error("ends where a search identifier was expected");
        }
        if (accept("not")) {
            return Expr.not(unary());
        }
        if (accept("(")) {
            Expr inner = or();
            if (!accept(")")) {
                throw error("misses a ')'");
            }
            return inner;
        }
        String token = tokens.get(next++);
        String quantifier = token.toLowerCase(Locale.ROOT);
        if ((quantifier.equals("1") || quantifier.equals("any") || quantifier.equals("all"))
                && accept("of")) {
            return quantified(quantifier.equals("all"));
        }
        if (token.equals("(") || token.equals(")") || isKeyword(token)) {
            throw error("has '" + token + "' where a search identifier was expected");
        }
        Expr search = searches.get(token);
        if (search == null) {
            throw error("names '" + token + "', which the detection does not define");
        }
        return search;
    }

    private Expr quantified(boolean all) {
        if (next >= tokens.size()) {
            throw error("ends after 'of'");
        }
        String target = tokens.get(next++);
        List<Expr> matched = new ArrayList<>();
        if (target.equalsIgnoreCase("them")) {
            searches.forEach(
                    (name, search) -> {
                        if (!name.startsWith("_")) {
                            matched.add(search);
                        }
                    });
        } else {
            Pattern pattern = glob(target);
            searches.forEach(
                    (name, search) -> {
                        if (pattern.matcher(name).matches()) {
                            matched.add(search);
                        }
                    });
        }
        if (matched.isEmpty()) {
            throw error("'of " + target + "' matches no search identifier");
        }
        return all ? Expr.and(matched) : Expr.or(matched);
    }

    private static Pattern glob(String pattern) {
        StringBuilder regex = new StringBuilder();
        for (String part : pattern.split("\\*", -1)) {
            if (!regex.isEmpty()) {
                regex.append(".*");
            }
            regex.append(Pattern.quote(part));
        }
        return Pattern.compile(regex.toString());
    }

    private static Aggregation aggregation(String text) {
        if (text.strip().toLowerCase(Locale.ROOT).startsWith("near")) {
            throw new SigmaException("the 'near' aggregation is not supported");
        }
        Matcher matcher = AGGREGATION.matcher(text);
        if (!matcher.matches()) {
            throw new SigmaException(
                    "aggregation '" + text.strip() + "' is not of the form count() by field > n");
        }
        String field = matcher.group(2).isEmpty() ? null : matcher.group(2);
        return new Aggregation(
                matcher.group(1).toLowerCase(Locale.ROOT),
                field,
                matcher.group(3),
                matcher.group(4),
                new BigDecimal(matcher.group(5)));
    }

    private boolean accept(String keyword) {
        if (next < tokens.size() && tokens.get(next).equalsIgnoreCase(keyword)) {
            next++;
            return true;
        }
        return false;
    }

    private static boolean isKeyword(String token) {
        return switch (token.toLowerCase(Locale.ROOT)) {
            case "and", "or", "not", "of", "them" -> true;
            default -> false;
        };
    }

    private SigmaException error(String problem) {
        return new SigmaException("condition '" + source.strip() + "' " + problem);
    }
}
