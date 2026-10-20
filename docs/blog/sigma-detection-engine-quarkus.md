---
title: "Running Sigma rules natively in a Quarkus SIEM: a converter, not an interpreter"
published: false
description: "How we import Sigma YAML into a small Java rule language, refuse what we cannot express faithfully, and run it over sliding event-time windows inside a Quarkus ingestion pipeline."
tags: java, quarkus, security, siem
cover_image: https://raw.githubusercontent.com/AI-SIEM-logs-analyzer/ai-siem-logs-analyzer/main/docs/screenshots/alerts.png
---

# Running Sigma rules natively in a Quarkus SIEM: a converter, not an interpreter

Every SIEM ends up with a detection engine, and every detection engine ends up with the same
question: *who writes the rules?* You can hand-craft a few: brute-force logins, SQL injection in
query strings, a scanner User-Agent. But the security community already maintains thousands of
detections in [Sigma](https://sigmahq.io/), a vendor-neutral YAML format for log signatures. Not
being able to read Sigma means rewriting the community's work by hand.

This post walks through how we added Sigma support to
[ai-siem-logs-analyzer](https://github.com/AI-SIEM-logs-analyzer/ai-siem-logs-analyzer), an
AI-assisted log analysis platform built on **Quarkus 3 and Java 21**. The short version:

- We don't interpret Sigma at runtime. We **convert** each Sigma rule into the engine's own small
  rule language, once, at import time.
- The converter **refuses** any rule it cannot express faithfully, and says why. It never
  approximates a rule into something that matches more or less than the original.
- Every converted rule is **parsed back** by the engine's parser before it is accepted. So what the
  importer stores is exactly what the engine will run.

All code below is from the repository, trimmed for length.

---

## The pipeline at a glance

```
  Sigma YAML ──► SigmaYaml ──► SigmaRule / SigmaCorrelation
                                    │
                                    ▼
                  SigmaConverter (+ SigmaFieldMapping)
                                    │   condition ──► Expr tree ──► rule-language text
                                    ▼
                  RuleExpressionParser.parse(text)   ◄── "does it really parse?"
                                    │
                                    ▼
             ConvertedRule ──► SigmaRuleImporter ──► alert_rule row (+ ATT&CK technique IDs)
                                                           │
  log upload ──► Kafka ──► DefaultLogFileParser ──► RuleEngine ──► Detection ──► Alert
```

Two packages keep the concerns apart:

- `detect` holds the rule language, its parser and the `RuleEngine`. It has no persistence, no CDI
  and no clock of its own. It reads `NormalizedEvent`s and returns `Detection`s.
- `detect.sigma` holds the Sigma reader and converter. It doesn't touch the database either.
  Storing rules is the job of one CDI service, `SigmaRuleImporter`.

That split is what makes the whole thing testable with plain JUnit, without booting Quarkus.

## Why convert in the JVM instead of using pySigma?

[pySigma](https://github.com/SigmaHQ/pySigma) is the reference toolchain, and it supports custom
backends. We considered writing a pySigma backend that emits our rule language. We chose an
in-JVM converter instead. The decision log in our architecture doc gives the reason:

> One converter, in the same build and test suite as the engine, keeps the field mapping and the
> rule language from drifting apart, and an import needs no Python toolchain. The converter refuses
> what it cannot express faithfully instead of approximating it.

The argument that decided it is *drift*. Change the rule language, and a converter in another
repo, in another language, quietly keeps emitting the old syntax. With the converter in the same
build, a converter test fails in the same `mvn verify` that changed the parser. pySigma is still
the fallback if the rules our importer refuses turn out to matter.

## The target: a small rule language

Before converting anything, you need something to convert *into*. The engine's rules are short
expressions stored as text in `alert_rule.expression`:

```
expression := condition ( '|' window )?
window     := aggregate ( 'by' field ( ',' field )* ) 'within' DURATION ( '>' | '>=' ) NUMBER
aggregate  := 'count' | 'distinct' '(' field ')' | 'sum' '(' field ')'
condition  := and ( 'or' and )*
and        := unary ( 'and' unary )*
unary      := 'not' unary | '(' condition ')' | 'true' | predicate
predicate  := field ( CMP literal | 'in' '(' literal, ... ')' | 'exists'
                    | ( 'contains' | 'startswith' | 'endswith' | 'matches' ) STRING )
```

A few real rules:

```
userAgent matches "(?i)sqlmap|nikto|nmap"
status in (401, 403) and path startswith "/login" | count by srcIp within 5m >= 10
status == 404 | distinct(path) by srcIp within 1m > 30
```

Everything left of the `|` is a per-event test. Everything right of it is an optional sliding
window. That is roughly the shape of a Sigma rule too: a detection, plus an optional aggregation
or correlation. So the mapping is natural, and the work is in the details.

## Step 1: Read YAML without trusting it

A Sigma file is untrusted input. Someone uploads it, and it may come from a public repo. The YAML
reader binds **no types**: it produces plain `Map`s, `List`s and scalars, so a rule file cannot
make Jackson instantiate anything.

```java
final class SigmaYaml {

    private static final YAMLMapper MAPPER =
            YAMLMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    static List<Map<String, Object>> read(String yaml) {
        List<Map<String, Object>> documents = new ArrayList<>();
        try (MappingIterator<Object> values = MAPPER.readerFor(Object.class).readValues(yaml)) {
            while (values.hasNextValue()) {
                Object document = values.nextValue();
                if (document == null) {
                    continue;
                }
                if (!(document instanceof Map<?, ?> map)) {
                    throw new SigmaException(
                            "document " + (documents.size() + 1) + " is not a YAML mapping");
                }
                documents.add(stringKeys(map));
            }
        } catch (JsonProcessingException e) {
            throw new SigmaException("not valid YAML: " + e.getOriginalMessage());
        } // ...
        return documents;
    }
}
```

`STRICT_DUPLICATE_DETECTION` is the subtle one. By default YAML parsers let the last duplicate key
win. In a detection, that means two `selection:` blocks silently collapse into one, and the rule
matches something different from what its author wrote. We'd rather fail loudly.

The reader also supports multi-document streams (`---`). Sigma 2 correlations need this, because
a correlation and the rules it counts usually live in the same file.

## Step 2: Fields and log sources

Sigma rules talk about `c-ip`, `cs-uri-stem` and `sc-status` (the W3C extended log names of
the `webserver` taxonomy), or about ECS names like `source.ip` and `url.path`. Our parsers produce
a `NormalizedEvent` with fields such as `srcIp`, `uriStem` and `status`. `SigmaFieldMapping` is
the dictionary between them:

```java
// Sigma webserver taxonomy: W3C extended log format names.
fields.put("c-ip", "srcIp");
fields.put("cs-method", "method");
fields.put("cs-uri-stem", "uriStem");
// The taxonomy means the query string, but SigmaHQ's web rules use it for the whole
// request target ('cs-uri-query|endswith: /mgmt/tm/util/bash'), so it reads path.
fields.put("cs-uri-query", "path");
fields.put("sc-status", "status");
fields.put("cs-user-agent", "userAgent");
// Elastic Common Schema, as JSON logs often name things.
fields.put("source.ip", "srcIp");
fields.put("url.path", "uriStem");
fields.put("user_agent.original", "userAgent");
// ...
```

Note the `cs-uri-query` comment. A field mapping that follows the spec to the letter would miss
real attacks, because the community rules use the field more loosely than the taxonomy defines
it. We found this by running SigmaHQ rules against real access-log lines in tests, as shown later.

A field that is not in the table falls back to `attributes.<name>`, where the JSON and syslog
parsers keep everything without a standard slot. A field name the rule language cannot spell,
such as `cs(Cookie)`, is refused rather than guessed at.

### Log sources become guards

This is the part people tend to skip, and it causes false positives. Our engine sees *every*
event, whatever file it came from. Take this rule:

```yaml
logsource:
    category: webserver
detection:
    success:
        sc-status: 200
    condition: not success
```

Converted naively to `not status == 200`, it fires on **every syslog line**, because syslog has no
HTTP status at all. So each `logsource` maps to a *guard* that is ANDed in front of the rule:

```java
List<LogsourceMapping> logsources =
        List.of(
                new LogsourceMapping("webserver", null, null, List.of("method exists")),
                new LogsourceMapping("", "apache", "access", http),
                new LogsourceMapping("", "nginx", "access", http),
                new LogsourceMapping("", "linux", "sshd", appName("sshd")),
                new LogsourceMapping("", "linux", "sudo", appName("sudo")),
                new LogsourceMapping("", "linux", "auth", syslog),
                // ...
                new LogsourceMapping("", "linux", "", syslog));
```

A Linux `sshd` rule therefore becomes:

```
format == "SYSLOG" and attributes.appName == "sshd" and raw contains "Accepted password for root"
```

A log source that matches no entry, such as a Windows `process_creation` rule, is **refused**:
`no mapping for log source {category: process_creation, product: windows}`. The platform ingests
access logs, syslog and JSON. A Windows rule has nothing to run against here, and pretending
otherwise would put a dead rule in the operator's list.

## Step 3: Values, wildcards and modifiers

Sigma string matching is case-insensitive by default, with `*` and `?` wildcards and backslash
escapes. `SigmaString` parses a value into literal parts and wildcard parts:

```java
final class SigmaString {
    private sealed interface Part {}
    private record Text(String value) implements Part {}
    private enum Wildcard implements Part { ANY, ONE }
    // ...
}
```

The converter then picks the **cheapest predicate that means the same thing**. A wildcard at one
end becomes `startswith` or `endswith`. Wildcards at both ends become `contains`. Only a wildcard
in the middle needs a regex. The converter's tests read like a spec, one Sigma value and its
conversion per line:

| Sigma | Rule language |
|---|---|
| `sc-status: [401, 403]` | `status in (401, 403)` |
| `cs-uri-stem: '*.php'` | `uriStem endswith ".php"` |
| `cs-uri-stem: '/wp-*'` | `uriStem startswith "/wp-"` |
| `cs-uri: '*passwd*'` | `path contains "passwd"` |
| `cs-uri-stem: '/admin*/login.php'` | `uriStem matches "(?is)^/admin.*/login\.php$"` |
| `cs-uri-stem\|contains\|cased: Admin` | `uriStem matches "Admin"` |
| `sc-bytes\|gt: 1000000` | `bytes > 1000000` |
| `cs-username: null` | `not user exists` |
| `cs-username: ''` | `(not user exists or user == "")` |

A few details are worth calling out:

- `cased` turns into a regex **without** the `(?i)` flag, because the rule language's string
  operators are case-insensitive by design.
- `base64offset` expands into the three encodings a value can take inside a longer base64 string,
  one per byte alignment. The characters that depend on the neighbours are cut off, as the Sigma
  spec describes.
- Keyword searches (a bare list of strings in a detection) match anywhere in the `raw` line.
- `cidr`, `windash`, `fieldref` and the UTF-16 encodings are refused with an explicit reason. They
  are not silently dropped.

## Step 4: Conditions as a sealed `Expr` tree

The Sigma `condition` (`selection and not filter`, `1 of selection_*`,
`all of them`) is parsed by a small recursive-descent parser, `SigmaConditionParser`, over search
identifiers that are *already converted*. Its output is an `Expr` tree, and this is where Java 21
features help:

```java
sealed interface Expr {
    record Leaf(String text) implements Expr {}
    record And(List<Expr> operands) implements Expr {}
    record Or(List<Expr> operands) implements Expr {}
    record Not(Expr operand) implements Expr {}

    /** The negation of {@code operand}; a double negation cancels out. */
    static Expr not(Expr operand) {
        return operand instanceof Not not ? not.operand() : new Not(operand);
    }
    // and()/or() flatten nested conjunctions/disjunctions
}
```

Rendering adds parentheses **only where precedence needs them**, so a converted rule reads like
one written by hand:

```java
private static void render(Expr expr, int context, StringBuilder text) {
    int precedence = precedence(expr);
    boolean parenthesize = precedence < context;
    if (parenthesize) {
        text.append('(');
    }
    switch (expr) {
        case Leaf leaf -> text.append(leaf.text());
        case Not not -> {
            text.append("not ");
            render(not.operand(), precedence, text);
        }
        case And and -> join(and.operands(), " and ", precedence, text);
        case Or or -> join(or.operands(), " or ", precedence, text);
    }
    if (parenthesize) {
        text.append(')');
    }
}

private static int precedence(Expr expr) {
    return switch (expr) {
        case Or or -> 1;
        case And and -> 2;
        case Not not -> 3;
        case Leaf leaf -> 4;
    };
}
```

Because `Expr` is sealed, both `switch`es are exhaustive and need no `default`. If someone adds a
fifth node type, the compiler points to every place that has to handle it.

Here is SigmaHQ's *Path Traversal Exploitation Attempts* rule:

```yaml
logsource:
    category: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '../../../etc/'
            - '%252e%252e%252fetc%252f'
    filter:
        sc-status: 404
    condition: selection and not filter
level: medium
```

It comes out as:

```
method exists and (path contains "../../../etc/" or path contains "%252e%252e%252fetc%252f") and not status == 404
```

## Step 5: Aggregations and correlations become sliding windows

Sigma has two ways to say "N of these within T":

- **Sigma 1 aggregations**: `condition: selection | count() by c-ip > 30` plus a `timeframe`.
- **Sigma 2 correlations**: a separate document of `type: event_count`, `value_count` or
  `value_sum` that counts the events matched by *other* rules.

Both map onto the engine's window clause: `count`, `distinct(field)` or `sum(field)`. Here is a
correlation:

```yaml
title: Failed login
name: failed_login
logsource:
    category: webserver
detection:
    selection:
        sc-status: [401, 403]
        cs-uri-stem|contains: login
    condition: selection
---
title: Login brute force
id: 0d5b2a4e-1c1e-4ad7-9d8a-6f2f1c1d0a11
level: high
correlation:
    type: event_count
    rules: failed_login
    group-by:
        - c-ip
    timespan: 5m
    condition:
        gte: 10
```

It converts to a single rule named `sigma-login-brute-force-0d5b2a4e` with severity `ERROR`:

```
method exists and status in (401, 403) and uriStem contains "login" | count by srcIp within 5m >= 10
```

As the Sigma spec requires, `failed_login` is **not** imported on its own unless the correlation
sets `generate: true`. Otherwise every single failed login would raise an alert as well as the
brute-force one.

### What we refuse, and why

The engine only supports **rising** thresholds (`>` and `>=`). This is deliberate, and the
`WindowSpec` javadoc explains why:

> The engine is driven by events, so it only ever looks at a window when an event arrives; "fewer
> than N in five minutes" would need a timer to notice the window closing with nothing in it, and
> would fire on the first event of every group besides.

So `count() < 5`, `near`, and `temporal` correlations are refused, each with a reason. Not
supporting a feature is acceptable. Converting `< 5` into something that fires on every new IP
address is not.

## Step 6: Trust, but parse

The last step of every conversion is the cheapest insurance in the whole design:

```java
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
```

A converter bug, such as a missing escape or a stray parenthesis, can never reach the database as
a rule that fails at ingestion time. It becomes a skipped document with a readable reason.

The result of an import is a `SigmaImport(List<ConvertedRule> rules, List<Skipped> skipped)`. One
bad document in a 500-rule file doesn't sink the other 499.

### Metadata is kept

The converter also carries the rule's context across:

- `level` maps onto the platform's severities: `informational`/`low` → `INFO`, `medium` →
  `WARNING`, `high` → `ERROR`, `critical` → `CRITICAL`.
- The description keeps the Sigma id, the author, the false positives and the references, so an
  analyst looking at an alert sees the same caveats the rule author wrote.
- Tags such as `attack.t1110` or `attack.t1595.003` become ATT&CK technique IDs (`T1110`,
  `T1595.003`). Tactic, group and software tags share the `attack.` prefix, but the regex
  `attack\.(t\d{4}(?:\.\d{3})?)` filters them out.
- `deprecated` and `unsupported` rules are skipped.

## The engine: event time, one window per group

A converted rule is just a `DetectionRule`, the same type as our hand-written rules. The
`RuleEngine` doesn't know Sigma exists.

Two design choices in the engine matter for imported rules.

**Windows run on event time, not on the wall clock.** Users upload log files, often from last week
or last month. If windows ran on `Instant.now()`, a replayed brute force would either be missed or
detected wrong. With event time, replaying a file detects exactly what a live feed would have.

**Each group gets its own sliding window, kept in a heap.** `GroupWindow` keeps events ordered by
timestamp, so a slightly out-of-order line still lands in the right window. The aggregate is
updated as events enter and leave, so reading it never rescans the window:

```java
boolean add(Instant at, Object contribution) {
    if (floor != null && at.isBefore(floor)) {
        return false;
    }
    if (latest == null || at.isAfter(latest)) {
        latest = at;
    }
    Instant horizon = latest.minus(spec.window());
    if (!at.isAfter(horizon)) {
        return false;
    }
    entries.add(new Entry(at, contribution));
    include(contribution);
    while (!entries.peek().at().isAfter(horizon)) {
        exclude(entries.poll().contribution());
    }
    return true;
}
```

When a window fires, it is **reset**, and a `floor` remembers where the burst ended:

```java
/**
 * Starting over is what keeps one burst from raising an alert on every event after the
 * threshold: ten failed logins fire once, and it takes ten more to fire again. The floor stops
 * a straggler from the burst that already fired from opening the next one.
 */
void reset() {
    entries.clear();
    distinct.clear();
    sum = BigDecimal.ZERO;
    floor = latest;
}
```

Memory stays bounded the same way. Every 1,024 matching events, a rule drops the groups that have
been quiet for longer than a window. "Quiet" is judged against the newest event the rule has seen,
again in event time.

## Wiring it into Quarkus

### Importing: idempotent, and it respects the operator

`SigmaRuleImporter` is the only piece that touches persistence. It's an `@ApplicationScoped` bean
with one `@Transactional` method:

```java
@Transactional
public Result importRules(String yaml) {
    SigmaImport converted = converter.convert(yaml);
    // ...
    for (ConvertedRule rule : converted.rules()) {
        Optional<AlertRule> stored = rules.findByName(rule.name());
        if (stored.isEmpty()) {
            AlertRule row = new AlertRule();
            rule.applyTo(row);
            rules.persist(row);
            created.add(rule.name());
        } else if (rule.matches(stored.get())) {
            unchanged.add(rule.name());
        } else {
            rule.applyTo(stored.get());
            updated.add(rule.name());
        }
    }
    return new Result(created, updated, unchanged, converted.skipped());
}
```

Two properties fall out of this:

1. **Re-importing is safe.** The name `sigma-<title-slug>-<first 8 chars of id>` is stable, so
   importing the same file twice changes nothing. Importing a newer revision of a rule updates its
   row in place.
2. **`enabled` is never touched on update.** If an analyst switched off a noisy rule, the next
   import of the SigmaHQ repo must not switch it back on.

### Detecting: inline, during ingestion

Uploads flow through Kafka (Redpanda locally). A `@Blocking` consumer hands each file to
`DefaultLogFileParser`, which builds a fresh `RuleEngine` from the enabled rules **per upload**:

```java
RuleEngine engine = new RuleEngine(enabledRules());
// for each line:
NormalizedEvent normalized = parseLine(line, format);
// ...
for (Detection detection : engine.evaluate(normalized)) {
    detections.add(new RaisedDetection(detection, logEvent));
}
```

Why one engine per upload? Because windows run on event time. A file from last month interleaved
with today's file would make every event in the older one look late.

Detections become alerts **in the same transaction** as the batch of events that triggered them
(`QuarkusTransaction.requiringNew()`), so there is never an alert pointing at an event that was
rolled back. A stored rule whose expression no longer parses is logged and skipped. It doesn't
fail the upload.

### From Sigma tag to ATT&CK matrix

`ConvertedRule.applyTo` writes the technique IDs into `alert_rule_technique`. When the rule
fires, the alert inherits those techniques. The techniques of the enabled rules also feed the
platform's MITRE ATT&CK matrix view and its alert filters. For an imported SigmaHQ rule, this
means its ATT&CK coverage comes from the tags its author already wrote.

## Testing against the real parsers

Unit tests on the converter (YAML in, expression text out) catch most regressions. They're
written as `@CsvSource` tables, so adding a case is one line:

```java
@ParameterizedTest
@CsvSource(delimiterString = "=>", quoteCharacter = '`', textBlock = """
        cs-method: POST => method == "POST"
        sc-status: [401, 403] => status in (401, 403)
        cs-uri-stem: '*.php' => uriStem endswith ".php"
        cs-referer|exists: false => not referrer exists
        """)
void convertsOneFieldValue(String selection, String expected) { /* ... */ }
```

But a conversion can be *syntactically* right and still *semantically* wrong, if the field it
reads isn't the field the parser fills in. So a second suite, `SigmaRuleEngineTest`, runs
converted rules through the real `RuleEngine`, over lines produced by the **production**
`AccessLogParser` and `SyslogParser`:

```java
List<Detection> fired =
        engine.evaluateAll(
                List.of(
                        request(ip, "/view?file=../../../etc/passwd", 200, "x", 1),
                        request(ip, "/view?f=%252e%252e%252fetc%252fhosts", 500, "x", 2),
                        // SigmaHQ's cs-uri-query means the whole target, path included.
                        request(ip, "/../../../etc/passwd", 403, "x", 3),
                        // Filtered out: the server did not have it.
                        request(ip, "/view?file=../../../etc/passwd", 404, "x", 4),
                        request(ip, "/index.html", 200, "x", 5)));

assertEquals(List.of(200, 500, 403), fired.stream().map(d -> d.trigger().status()).toList());
```

This suite is where the `cs-uri-query → path` decision and the log-source guards came from. Both
were invisible in pure converter tests.

## Limits, honestly

- **Log sources:** web access logs, Linux syslog and JSON. No Windows, proxy or cloud audit rules
  yet. Those are refused, not converted.
- **Modifiers:** no `cidr`, `windash`, `fieldref` or UTF-16 encodings.
- **Conditions:** no falling thresholds, `near` or `temporal` correlations, because the engine is
  event-driven.
- **API:** the importer is a tested CDI service, but nothing calls it from the outside yet. The
  rule-management API that will hand it a file is the next step.

## Takeaways

1. **Convert, don't interpret.** A small native rule language plus a converter keeps the runtime
   simple and fast, and the imported rules readable and editable by analysts.
2. **Refuse instead of approximating.** In detection, a rule that silently means something else is
   worse than a missing rule. Make "skipped, with a reason" a normal, first-class outcome.
3. **Parse your own output.** One call to your own parser turns a whole class of converter bugs
   into import-time errors.
4. **Log sources are semantics, not metadata.** Without guards, negated rules fire on every
   unrelated event.
5. **Test against real parsers.** Field mappings only become correct when they meet real log
   lines.

The code lives in `backend/src/main/java/com/siem/analyzer/detect/sigma/` in the
[repository](https://github.com/AI-SIEM-logs-analyzer/ai-siem-logs-analyzer). Feedback and Sigma
rules that break the converter are both welcome.
