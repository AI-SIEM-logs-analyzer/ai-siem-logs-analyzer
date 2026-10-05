package com.siem.analyzer.detect;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Parses the rule language stored in {@code alert_rule.expression}.
 *
 * <pre>
 * expression := condition ( '|' window )?
 * window     := aggregate ( 'by' field ( ',' field )* )? 'within' DURATION ( '&gt;' | '&gt;=' ) NUMBER
 * aggregate  := 'count' ( '(' ')' )? | 'distinct' '(' field ')' | 'sum' '(' field ')'
 * condition  := and ( 'or' and )*
 * and        := unary ( 'and' unary )*
 * unary      := 'not' unary | '(' condition ')' | 'true' | predicate
 * predicate  := field ( CMP literal | 'in' '(' literal ( ',' literal )* ')' | 'exists'
 *                     | ( 'contains' | 'startswith' | 'endswith' | 'matches' ) STRING )
 * CMP        := '==' | '!=' | '&gt;' | '&gt;=' | '&lt;' | '&lt;='
 * literal    := STRING | NUMBER | 'true' | 'false'
 * DURATION   := integer followed by s, m, h or d — 30s, 5m, 1h, 1d
 * </pre>
 *
 * <p>Keywords are case-insensitive; {@code not} binds tighter than {@code and}, which binds tighter
 * than {@code or}. Strings take double or single quotes, with backslash escaping the quote, a
 * backslash, {@code \n} and {@code \t}. Field names are those of {@link EventField}. Some rules:
 *
 * <pre>
 * userAgent matches "(?i)sqlmap|nikto|nmap"
 * status in (401, 403) and path startswith "/login" | count by srcIp within 5m &gt;= 10
 * status == 404 | distinct(path) by srcIp within 1m &gt; 30
 * method == "GET" | sum(bytes) by srcIp within 10m &gt; 500000000
 * </pre>
 *
 * <p>The window clause's semantics are described on {@link WindowSpec} and {@link RuleEngine}.
 */
public final class RuleExpressionParser {

    private final String source;
    private final List<Token> tokens;
    private int next;

    private RuleExpressionParser(String source) {
        this.source = source;
        this.tokens = tokenize(source);
    }

    /**
     * Parses a rule expression.
     *
     * @throws RuleSyntaxException the text is not a valid expression
     */
    public static RuleExpression parse(String source) {
        if (source == null || source.isBlank()) {
            throw new RuleSyntaxException("the expression is empty", 0);
        }
        return new RuleExpressionParser(source).expression();
    }

    private RuleExpression expression() {
        Condition condition = or();
        WindowSpec window = acceptSymbol("|") ? window() : null;
        Token end = peek();
        if (end.type() != TokenType.END) {
            throw error("unexpected '" + end.text() + "'", end);
        }
        return new RuleExpression(condition, window);
    }

    // --- conditions ------------------------------------------------------------------------

    private Condition or() {
        List<Condition> operands = new ArrayList<>(List.of(and()));
        while (acceptKeyword("or")) {
            operands.add(and());
        }
        return operands.size() == 1 ? operands.get(0) : new Condition.Or(operands);
    }

    private Condition and() {
        List<Condition> operands = new ArrayList<>(List.of(unary()));
        while (acceptKeyword("and")) {
            operands.add(unary());
        }
        return operands.size() == 1 ? operands.get(0) : new Condition.And(operands);
    }

    private Condition unary() {
        if (acceptKeyword("not")) {
            return new Condition.Not(unary());
        }
        if (acceptSymbol("(")) {
            Condition inner = or();
            expectSymbol(")");
            return inner;
        }
        if (acceptKeyword("true")) {
            return new Condition.Always();
        }
        return predicate();
    }

    private Condition predicate() {
        EventField field = field();
        if (acceptKeyword("exists")) {
            return new Condition.Exists(field);
        }
        if (acceptKeyword("in")) {
            expectSymbol("(");
            List<Object> operands = new ArrayList<>(List.of(literal()));
            while (acceptSymbol(",")) {
                operands.add(literal());
            }
            expectSymbol(")");
            return new Condition.In(field, operands);
        }
        if (acceptKeyword("matches")) {
            Token pattern = expect(TokenType.STRING, "a quoted regular expression");
            try {
                return new Condition.Matches(field, Pattern.compile((String) pattern.value()));
            } catch (PatternSyntaxException e) {
                throw error("invalid regular expression: " + e.getDescription(), pattern);
            }
        }
        for (Operator text : List.of(Operator.CONTAINS, Operator.STARTS_WITH, Operator.ENDS_WITH)) {
            if (acceptKeyword(text.symbol())) {
                Token operand = expect(TokenType.STRING, "a quoted string");
                return new Condition.Compare(field, text, operand.value());
            }
        }
        Token token = peek();
        Operator comparison = comparison(token);
        if (comparison == null) {
            throw error(
                    "expected an operator after '"
                            + field.name()
                            + "' (==, !=, >, >=, <, <=, in, exists, contains, startswith,"
                            + " endswith, matches)",
                    token);
        }
        next++;
        Token operand = peek();
        Object value = literal();
        if (comparison.isOrdering() && !(value instanceof BigDecimal)) {
            throw error("'" + comparison.symbol() + "' compares numbers only", operand);
        }
        return new Condition.Compare(field, comparison, value);
    }

    private static Operator comparison(Token token) {
        if (token.type() != TokenType.SYMBOL) {
            return null;
        }
        for (Operator operator : List.of(Operator.EQ, Operator.NE, Operator.GE, Operator.LE)) {
            if (operator.symbol().equals(token.text())) {
                return operator;
            }
        }
        return switch (token.text()) {
            case ">" -> Operator.GT;
            case "<" -> Operator.LT;
            default -> null;
        };
    }

    private Object literal() {
        Token token = peek();
        switch (token.type()) {
            case STRING, NUMBER -> {
                next++;
                return token.value();
            }
            case IDENTIFIER -> {
                // Bare true/false compare as text, which is how a JSON boolean reads.
                if (isKeyword(token, "true") || isKeyword(token, "false")) {
                    next++;
                    return token.text().toLowerCase(Locale.ROOT);
                }
            }
            default -> {
                // Falls through to the error below.
            }
        }
        throw error("expected a quoted string or a number", token);
    }

    private EventField field() {
        Token token = expect(TokenType.IDENTIFIER, "a field name");
        try {
            return EventField.named(token.text());
        } catch (IllegalArgumentException e) {
            throw error(e.getMessage(), token);
        }
    }

    // --- window clause ---------------------------------------------------------------------

    private WindowSpec window() {
        Aggregation aggregation = aggregation();
        List<EventField> groupBy = new ArrayList<>();
        if (acceptKeyword("by")) {
            groupBy.add(field());
            while (acceptSymbol(",")) {
                groupBy.add(field());
            }
        }
        if (!acceptKeyword("within")) {
            throw error("expected 'within <duration>', for example 'within 5m'", peek());
        }
        Duration window =
                (Duration) expect(TokenType.DURATION, "a duration such as 30s or 5m").value();

        Token operatorToken = peek();
        Operator operator = comparison(operatorToken);
        if (operator != Operator.GT && operator != Operator.GE) {
            throw error(
                    "expected '>' or '>=' and a threshold; a window can only fire when a value"
                            + " rises",
                    operatorToken);
        }
        next++;
        Token thresholdToken = expect(TokenType.NUMBER, "a threshold number");
        BigDecimal threshold = (BigDecimal) thresholdToken.value();
        if (threshold.signum() < 0) {
            throw error("the threshold must not be negative", thresholdToken);
        }
        return new WindowSpec(aggregation, groupBy, window, operator, threshold);
    }

    private Aggregation aggregation() {
        if (acceptKeyword("count")) {
            if (acceptSymbol("(")) {
                expectSymbol(")");
            }
            return new Aggregation.Count();
        }
        if (acceptKeyword("distinct")) {
            expectSymbol("(");
            EventField field = field();
            expectSymbol(")");
            return new Aggregation.DistinctCount(field);
        }
        if (acceptKeyword("sum")) {
            expectSymbol("(");
            EventField field = field();
            expectSymbol(")");
            return new Aggregation.Sum(field);
        }
        throw error("expected count, distinct(<field>) or sum(<field>) after '|'", peek());
    }

    // --- token stream ----------------------------------------------------------------------

    private Token peek() {
        return tokens.get(next);
    }

    private boolean acceptKeyword(String keyword) {
        if (isKeyword(peek(), keyword)) {
            next++;
            return true;
        }
        return false;
    }

    private static boolean isKeyword(Token token, String keyword) {
        return token.type() == TokenType.IDENTIFIER && token.text().equalsIgnoreCase(keyword);
    }

    private boolean acceptSymbol(String symbol) {
        Token token = peek();
        if (token.type() == TokenType.SYMBOL && token.text().equals(symbol)) {
            next++;
            return true;
        }
        return false;
    }

    private void expectSymbol(String symbol) {
        if (!acceptSymbol(symbol)) {
            throw error("expected '" + symbol + "'", peek());
        }
    }

    private Token expect(TokenType type, String what) {
        Token token = peek();
        if (token.type() != type) {
            throw error("expected " + what, token);
        }
        next++;
        return token;
    }

    private RuleSyntaxException error(String message, Token token) {
        String found =
                token.type() == TokenType.END ? "end of expression" : "'" + token.text() + "'";
        return new RuleSyntaxException(
                message + ", found " + found, Math.min(token.position(), source.length()));
    }

    // --- tokenizer -------------------------------------------------------------------------

    private enum TokenType {
        IDENTIFIER,
        STRING,
        NUMBER,
        DURATION,
        SYMBOL,
        END
    }

    private record Token(TokenType type, String text, Object value, int position) {}

    private static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < source.length()) {
            char c = source.charAt(i);
            int start = i;
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '"' || c == '\'') {
                StringBuilder text = new StringBuilder();
                i++;
                while (true) {
                    if (i >= source.length()) {
                        throw new RuleSyntaxException("unterminated string", start);
                    }
                    char ch = source.charAt(i++);
                    if (ch == c) {
                        break;
                    }
                    if (ch == '\\') {
                        if (i >= source.length()) {
                            throw new RuleSyntaxException("unterminated string", start);
                        }
                        char escaped = source.charAt(i++);
                        switch (escaped) {
                            case 'n' -> text.append('\n');
                            case 't' -> text.append('\t');
                            case '\\', '"', '\'' -> text.append(escaped);
                            // A regex escape such as \d or \. is kept as written, so patterns
                            // need no doubled backslashes.
                            default -> text.append('\\').append(escaped);
                        }
                    } else {
                        text.append(ch);
                    }
                }
                tokens.add(
                        new Token(
                                TokenType.STRING,
                                source.substring(start, i),
                                text.toString(),
                                start));
            } else if (isDigit(c)
                    || (c == '-' && i + 1 < source.length() && isDigit(source.charAt(i + 1)))) {
                i++;
                while (i < source.length()
                        && (isDigit(source.charAt(i)) || source.charAt(i) == '.')) {
                    i++;
                }
                String number = source.substring(start, i);
                int unitStart = i;
                while (i < source.length() && Character.isLetter(source.charAt(i))) {
                    i++;
                }
                if (i > unitStart) {
                    String text = source.substring(start, i);
                    tokens.add(
                            new Token(
                                    TokenType.DURATION,
                                    text,
                                    duration(number, source.substring(unitStart, i), start),
                                    start));
                } else {
                    try {
                        tokens.add(
                                new Token(TokenType.NUMBER, number, new BigDecimal(number), start));
                    } catch (NumberFormatException e) {
                        throw new RuleSyntaxException("invalid number '" + number + "'", start);
                    }
                }
            } else if (Character.isLetter(c) || c == '_') {
                i++;
                while (i < source.length() && isIdentifierPart(source.charAt(i))) {
                    i++;
                }
                String text = source.substring(start, i);
                tokens.add(new Token(TokenType.IDENTIFIER, text, text, start));
            } else {
                String two = source.substring(i, Math.min(i + 2, source.length()));
                String symbol;
                if (two.equals("==") || two.equals("!=") || two.equals(">=") || two.equals("<=")) {
                    symbol = two;
                } else if ("()|,<>".indexOf(c) >= 0) {
                    symbol = String.valueOf(c);
                } else if (c == '=') {
                    throw new RuleSyntaxException("use '==' to compare, not '='", start);
                } else {
                    throw new RuleSyntaxException("unexpected character '" + c + "'", start);
                }
                i += symbol.length();
                tokens.add(new Token(TokenType.SYMBOL, symbol, symbol, start));
            }
        }
        tokens.add(new Token(TokenType.END, "", null, source.length()));
        return tokens;
    }

    private static Duration duration(String amount, String unit, int position) {
        long value;
        try {
            value = Long.parseLong(amount);
        } catch (NumberFormatException e) {
            throw new RuleSyntaxException(
                    "a duration takes a whole number, not '" + amount + "'", position);
        }
        if (value <= 0) {
            throw new RuleSyntaxException("a duration must be positive", position);
        }
        return switch (unit.toLowerCase(Locale.ROOT)) {
            case "s" -> Duration.ofSeconds(value);
            case "m" -> Duration.ofMinutes(value);
            case "h" -> Duration.ofHours(value);
            case "d" -> Duration.ofDays(value);
            default ->
                    throw new RuleSyntaxException(
                            "unknown duration unit '" + unit + "'; use s, m, h or d", position);
        };
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    /** Hyphens are allowed so attribute keys such as {@code x-forwarded-for} need no quoting. */
    private static boolean isIdentifierPart(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '-';
    }
}
