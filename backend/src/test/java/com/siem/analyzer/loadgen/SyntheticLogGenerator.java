package com.siem.analyzer.loadgen;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.SplittableRandom;
import java.util.UUID;

/**
 * Writes synthetic, benign log files for exercising ingestion, indexing and search at scale.
 *
 * <p>Three streams are produced, one wire format each, because {@code LogFormatDetector} decides
 * the format of an upload from its first line and a mixed file would be read as one format only:
 *
 * <ul>
 *   <li>{@code access-NNNN.log} — nginx Combined Log Format: shoppers browsing pages, assets and
 *       API calls, plus search-engine crawlers;
 *   <li>{@code syslog-NNNN.log} — RFC 5424 syslog from a small server fleet: SSH key logins, cron,
 *       systemd units, sudo by administrators, PostgreSQL checkpoints;
 *   <li>{@code app-NNNN.ndjson} — ECS-style JSON application events with a unique {@code id}, so
 *       uploading the same file twice is deduplicated.
 * </ul>
 *
 * <p>Timestamps follow a day/night curve over the requested span and are written in order. Users,
 * their addresses and browsers are drawn once and reused, so per-user and per-address aggregations
 * look like real traffic rather than uniform noise. Output is fully determined by the options: the
 * same seed and start produce byte-identical files.
 *
 * <p>Generation streams line by line, so memory stays flat however many events are requested. A
 * stream rolls over to a new file before it passes {@code --max-file-bytes}, which defaults below
 * the 50 MiB upload limit so every file can be uploaded as it is.
 *
 * <p>The class depends on the JDK alone, so it runs without a build:
 *
 * <pre>
 * java backend/src/test/java/com/siem/analyzer/loadgen/SyntheticLogGenerator.java --events 250000
 * </pre>
 */
public final class SyntheticLogGenerator {

    /** One output stream: its file prefix, extension and share of the events. */
    public enum Stream {
        ACCESS("access", "log", 6),
        SYSLOG("syslog", "log", 2),
        JSON("app", "ndjson", 2);

        private final String prefix;
        private final String extension;
        private final int weight;

        Stream(String prefix, String extension, int weight) {
            this.prefix = prefix;
            this.extension = extension;
            this.weight = weight;
        }

        public String prefix() {
            return prefix;
        }

        public String extension() {
            return extension;
        }
    }

    /**
     * What to generate.
     *
     * @param events total number of lines across all streams
     * @param outDir directory the files are written to; created when missing
     * @param seed seed of the random generator
     * @param start timestamp of the beginning of the span
     * @param span how much time the events cover
     * @param streams which streams to write
     * @param maxFileBytes a file is rolled over before it grows past this size
     */
    public record Options(
            long events,
            Path outDir,
            long seed,
            Instant start,
            Duration span,
            Set<Stream> streams,
            long maxFileBytes) {

        public static final long DEFAULT_EVENTS = 100_000;
        public static final long DEFAULT_SEED = 42;
        public static final Duration DEFAULT_SPAN = Duration.ofDays(1);

        /** 48 MiB: under the 50 MiB upload limit with room for a line that crosses it. */
        public static final long DEFAULT_MAX_FILE_BYTES = 48L * 1024 * 1024;

        public Options {
            if (events < 0) {
                throw new IllegalArgumentException("events must not be negative");
            }
            if (span.isNegative() || span.toMinutes() < 1) {
                throw new IllegalArgumentException("span must be at least one minute");
            }
            if (streams.isEmpty()) {
                throw new IllegalArgumentException("at least one stream is needed");
            }
            if (maxFileBytes < 4096) {
                throw new IllegalArgumentException("max-file-bytes must be at least 4096");
            }
            streams = Set.copyOf(streams);
        }

        /** Defaults: 100k events over the last day, every stream, into {@code outDir}. */
        public static Options defaults(Path outDir) {
            Instant now = Instant.now().truncatedTo(ChronoUnit.MINUTES);
            return new Options(
                    DEFAULT_EVENTS,
                    outDir,
                    DEFAULT_SEED,
                    now.minus(DEFAULT_SPAN),
                    DEFAULT_SPAN,
                    EnumSet.allOf(Stream.class),
                    DEFAULT_MAX_FILE_BYTES);
        }

        static Options parse(String[] args) {
            Options options = defaults(Path.of("target", "synthetic-logs"));
            long events = options.events();
            Path outDir = options.outDir();
            long seed = options.seed();
            Instant start = null;
            Duration span = options.span();
            Set<Stream> streams = options.streams();
            long maxFileBytes = options.maxFileBytes();

            for (int i = 0; i < args.length; i++) {
                String flag = args[i];
                if ("--help".equals(flag) || "-h".equals(flag)) {
                    throw new UsageException(null);
                }
                if (i + 1 >= args.length) {
                    throw new UsageException("missing value for " + flag);
                }
                String value = args[++i];
                switch (flag) {
                    case "--events" -> events = Long.parseLong(value.replace("_", ""));
                    case "--out" -> outDir = Path.of(value);
                    case "--seed" -> seed = Long.parseLong(value);
                    case "--start" -> start = Instant.parse(value);
                    case "--span" -> span = Duration.parse(value);
                    case "--streams" -> streams = parseStreams(value);
                    case "--max-file-bytes" -> maxFileBytes = Long.parseLong(value);
                    default -> throw new UsageException("unknown option " + flag);
                }
            }
            if (start == null) {
                start = Instant.now().truncatedTo(ChronoUnit.MINUTES).minus(span);
            }
            return new Options(events, outDir, seed, start, span, streams, maxFileBytes);
        }

        private static Set<Stream> parseStreams(String value) {
            Set<Stream> streams = EnumSet.noneOf(Stream.class);
            for (String name : value.split(",")) {
                streams.add(Stream.valueOf(name.strip().toUpperCase(Locale.ROOT)));
            }
            return streams;
        }
    }

    /**
     * What was written.
     *
     * @param events lines written across every file
     * @param linesPerFile lines per file name, in the order the files were opened
     * @param linesPerStream lines per stream
     */
    public record Summary(
            long events, Map<String, Long> linesPerFile, Map<Stream, Long> linesPerStream) {}

    /** Bad command line; a {@code null} message asks for the usage text alone. */
    static final class UsageException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }

    private static final String USAGE =
            """
            Usage: SyntheticLogGenerator [options]
              --events N           total lines across all streams (default 100000)
              --out DIR            output directory (default target/synthetic-logs)
              --seed N             random seed (default 42)
              --start INSTANT      start of the span, e.g. 2026-09-24T00:00:00Z (default: now - span)
              --span DURATION      time covered, ISO-8601, e.g. PT6H or P7D (default P1D)
              --streams LIST       any of access,syslog,json (default all)
              --max-file-bytes N   roll a file over before this size (default 50331648)
            """;

    /** Relative traffic per hour of the day, UTC: a night trough and an afternoon peak. */
    private static final double[] HOURLY_WEIGHT = {
        0.20, 0.15, 0.12, 0.10, 0.10, 0.12, 0.20, 0.35, 0.55, 0.75, 0.85, 0.90,
        0.95, 1.00, 1.00, 0.95, 0.90, 0.85, 0.80, 0.75, 0.65, 0.50, 0.40, 0.30
    };

    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)
                    .withZone(ZoneOffset.UTC);

    private static final DateTimeFormatter ISO_MILLIS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX").withZone(ZoneOffset.UTC);

    private static final String SITE = "https://shop.example.com";

    private static final String[] FIRST_NAMES = {
        "ana", "andrei", "maria", "ion", "elena", "mihai", "ioana", "alex", "cristina", "vlad",
        "diana", "radu", "laura", "paul", "irina", "george", "oana", "dan", "sofia", "matei"
    };

    private static final String[] LAST_NAMES = {
        "popescu",
        "ionescu",
        "stan",
        "dumitru",
        "georgescu",
        "marin",
        "tudor",
        "constantin",
        "rusu",
        "munteanu",
        "lazar",
        "matei",
        "ene",
        "barbu",
        "nistor"
    };

    private static final String[] BROWSER_AGENTS = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                + " Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
                + " Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
                + " Chrome/127.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15"
                + " (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko)"
                + " Chrome/128.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                + " Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
    };

    private static final String[] CRAWLER_AGENTS = {
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)"
    };

    private static final String[] PAGES = {
        "/", "/products", "/cart", "/checkout", "/account", "/about", "/contact", "/help"
    };

    private static final String[] SEARCH_TERMS = {
        "laptop", "headphones", "coffee+grinder", "running+shoes", "backpack", "desk+lamp"
    };

    private static final String[] BLOG_SLUGS = {
        "spring-sale", "gift-guide", "how-to-choose-a-laptop", "shipping-update", "new-arrivals"
    };

    private static final String[] WEB_HOSTS = {"web-01", "web-02", "web-03"};

    private static final String[] APP_HOSTS = {"app-01", "app-02"};

    private static final String[] SERVER_HOSTS = {
        "web-01", "web-02", "web-03", "app-01", "app-02", "db-01", "bastion-01"
    };

    private static final String[] ADMINS = {"ops.ana", "ops.radu", "deploy"};

    private static final String[] SUDO_COMMANDS = {
        "/usr/bin/systemctl restart nginx",
        "/usr/bin/systemctl status postgresql",
        "/usr/bin/apt-get update",
        "/usr/bin/journalctl -u nginx --since today",
        "/usr/bin/tail -n 200 /var/log/nginx/error.log"
    };

    private static final String[] SYSTEMD_MESSAGES = {
        "Started Daily apt download activities.",
        "Finished logrotate.service - Rotate log files.",
        "Starting Cleanup of Temporary Directories...",
        "Finished systemd-tmpfiles-clean.service - Cleanup of Temporary Directories.",
        "Started Daily man-db regeneration.",
        "Reloaded nginx.service - A high performance web server and a reverse proxy server."
    };

    private static final String[] CRON_JOBS = {
        "/usr/local/bin/backup.sh --incremental",
        "/usr/lib/php/sessionclean",
        "test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily",
        "/usr/local/bin/refresh-sitemap"
    };

    private static final String[] APP_SERVICES = {"storefront", "orders", "accounts"};

    /** Syslog facility codes used below; priority is facility * 8 + severity. */
    private static final int KERN = 0;

    private static final int DAEMON = 3;
    private static final int CRON = 9;
    private static final int AUTHPRIV = 10;
    private static final int LOCAL0 = 16;

    private static final int WARNING = 4;
    private static final int NOTICE = 5;
    private static final int INFO = 6;

    private final Options options;
    private final SplittableRandom random;
    private final List<Person> people;
    private final List<String> crawlerIps;
    private final Stream[] streamTable;
    private final String assetHash;

    private SyntheticLogGenerator(Options options) {
        this.options = options;
        this.random = new SplittableRandom(options.seed());
        this.people = new ArrayList<>();
        int population = (int) Math.max(50, Math.min(20_000, options.events() / 50));
        for (int i = 0; i < population; i++) {
            people.add(newPerson(i));
        }
        this.crawlerIps = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            crawlerIps.add(publicIp());
        }
        this.streamTable = streamTable(options.streams());
        this.assetHash = Long.toHexString(random.nextLong() & 0xffffffffL);
    }

    public static void main(String[] args) throws IOException {
        Options options;
        try {
            options = Options.parse(args);
        } catch (UsageException | IllegalArgumentException e) {
            if (e.getMessage() != null) {
                System.err.println("error: " + e.getMessage());
            }
            System.err.print(USAGE);
            System.exit(e.getMessage() == null ? 0 : 2);
            return;
        }

        long began = System.nanoTime();
        Summary summary = generate(options);
        long millis = Duration.ofNanos(System.nanoTime() - began).toMillis();

        System.out.printf(
                "Wrote %,d events to %s in %,d ms%n",
                summary.events(), options.outDir().toAbsolutePath(), millis);
        summary.linesPerFile()
                .forEach((file, lines) -> System.out.printf("  %-20s %,10d%n", file, lines));
    }

    /** Writes the files and a {@code manifest.json} describing them. */
    public static Summary generate(Options options) throws IOException {
        Files.createDirectories(options.outDir());
        return new SyntheticLogGenerator(options).run();
    }

    private Summary run() throws IOException {
        Map<Stream, RollingWriter> writers = new EnumMap<>(Stream.class);
        for (Stream stream : options.streams()) {
            writers.put(
                    stream, new RollingWriter(options.outDir(), stream, options.maxFileBytes()));
        }

        long minutes = options.span().toMinutes();
        double totalWeight = 0;
        for (long m = 0; m < minutes; m++) {
            totalWeight += weightOf(m);
        }

        long written = 0;
        double carry = 0;
        try {
            for (long m = 0; m < minutes; m++) {
                // Largest-remainder rounding keeps the curve and hits the requested total exactly.
                double exact = options.events() * weightOf(m) / totalWeight + carry;
                long count = (long) exact;
                carry = exact - count;
                if (m == minutes - 1) {
                    count = options.events() - written;
                }
                Instant minuteStart = options.start().plus(Duration.ofMinutes(m));
                for (int offset : sortedOffsets(count)) {
                    Instant at = minuteStart.plusMillis(offset);
                    Stream stream = streamTable[random.nextInt(streamTable.length)];
                    writers.get(stream).write(line(stream, at));
                }
                written += count;
            }
        } finally {
            for (RollingWriter writer : writers.values()) {
                writer.close();
            }
        }

        Map<String, Long> perFile = new LinkedHashMap<>();
        Map<Stream, Long> perStream = new EnumMap<>(Stream.class);
        for (Map.Entry<Stream, RollingWriter> entry : writers.entrySet()) {
            perFile.putAll(entry.getValue().linesPerFile);
            perStream.put(entry.getKey(), entry.getValue().totalLines);
        }
        Summary summary = new Summary(written, perFile, perStream);
        writeManifest(summary);
        return summary;
    }

    private double weightOf(long minute) {
        Instant at = options.start().plus(Duration.ofMinutes(minute));
        return HOURLY_WEIGHT[at.atZone(ZoneOffset.UTC).getHour()];
    }

    private int[] sortedOffsets(long count) {
        int[] offsets = new int[Math.toIntExact(count)];
        for (int i = 0; i < offsets.length; i++) {
            offsets[i] = random.nextInt(60_000);
        }
        Arrays.sort(offsets);
        return offsets;
    }

    private String line(Stream stream, Instant at) {
        return switch (stream) {
            case ACCESS -> accessLine(at);
            case SYSLOG -> syslogLine(at);
            case JSON -> jsonLine(at);
        };
    }

    // --- access log ---------------------------------------------------------------------------

    private String accessLine(Instant at) {
        boolean crawler = random.nextInt(100) < 6;
        Person person = crawler ? null : pick(people);
        String ip = crawler ? pick(crawlerIps) : person.ip();
        String agent = crawler ? pick(CRAWLER_AGENTS) : person.userAgent();
        String authUser = !crawler && random.nextInt(100) < 5 ? person.userName() : "-";

        String method = "GET";
        String path;
        int status = 200;
        long bytes;
        int kind = random.nextInt(100);
        if (crawler || kind < 45) {
            path = pagePath();
            bytes = sizeAround(18_000);
        } else if (kind < 80) {
            path = assetPath();
            bytes = sizeAround(40_000);
            if (random.nextInt(100) < 25) {
                status = 304;
            }
        } else {
            int api = random.nextInt(10);
            if (api < 6) {
                path = "/api/v1/products?page=" + (1 + random.nextInt(20));
            } else if (api < 8) {
                method = "POST";
                path = "/api/v1/cart/items";
                status = 201;
            } else {
                path = "/api/v1/orders/" + (100_000 + random.nextInt(900_000));
            }
            bytes = sizeAround(2_500);
        }

        int roll = random.nextInt(1000);
        if (roll < 15) {
            status = 404;
        } else if (roll < 20) {
            status = 301;
        } else if (roll < 22) {
            status = 500;
        } else if (roll < 30 && "GET".equals(method)) {
            method = "HEAD";
        }
        if (status == 304 || status == 301 || "HEAD".equals(method)) {
            bytes = 0;
        } else if (status == 404 || status == 500) {
            bytes = sizeAround(600);
        }

        String referrer =
                crawler || random.nextInt(100) < 30 ? "-" : SITE + PAGES[random.nextInt(4)];
        return ip
                + " - "
                + authUser
                + " ["
                + HTTP_DATE.format(at)
                + "] \""
                + method
                + " "
                + path
                + " HTTP/1.1\" "
                + status
                + " "
                + bytes
                + " \""
                + referrer
                + "\" \""
                + agent
                + "\"";
    }

    private String pagePath() {
        int kind = random.nextInt(10);
        if (kind < 4) {
            return pick(PAGES);
        }
        if (kind < 7) {
            return "/products/" + (1000 + random.nextInt(4000));
        }
        if (kind < 9) {
            return "/search?q=" + pick(SEARCH_TERMS);
        }
        return "/blog/" + pick(BLOG_SLUGS);
    }

    private String assetPath() {
        return switch (random.nextInt(4)) {
            case 0 -> "/static/css/main." + assetHash + ".css";
            case 1 -> "/static/js/app." + assetHash + ".js";
            case 2 -> "/images/products/" + (1000 + random.nextInt(4000)) + ".webp";
            default -> "/favicon.ico";
        };
    }

    // --- syslog -------------------------------------------------------------------------------

    private String syslogLine(Instant at) {
        String host = pick(SERVER_HOSTS);
        int pid = 1000 + random.nextInt(60_000);
        int kind = random.nextInt(100);
        if (kind < 22) {
            String admin = pick(ADMINS);
            int port = 40_000 + random.nextInt(25_000);
            String message =
                    switch (random.nextInt(3)) {
                        case 0 ->
                                "Accepted publickey for "
                                        + admin
                                        + " from 10.20."
                                        + random.nextInt(4)
                                        + "."
                                        + (10 + random.nextInt(200))
                                        + " port "
                                        + port
                                        + " ssh2: ED25519 SHA256:"
                                        + fingerprint(admin);
                        case 1 ->
                                "pam_unix(sshd:session): session opened for user "
                                        + admin
                                        + "(uid="
                                        + uid(admin)
                                        + ") by (uid=0)";
                        default -> "pam_unix(sshd:session): session closed for user " + admin;
                    };
            return syslog(at, AUTHPRIV, INFO, host, "sshd", pid, message);
        }
        if (kind < 45) {
            String message =
                    random.nextBoolean()
                            ? "pam_unix(cron:session): session opened for user root(uid=0) by"
                                    + " (uid=0)"
                            : "(root) CMD (" + pick(CRON_JOBS) + ")";
            return syslog(at, CRON, INFO, host, "CRON", pid, message);
        }
        if (kind < 70) {
            return syslog(at, DAEMON, INFO, host, "systemd", 1, pick(SYSTEMD_MESSAGES));
        }
        if (kind < 80) {
            String admin = pick(ADMINS);
            String message =
                    admin
                            + " : TTY=pts/"
                            + random.nextInt(4)
                            + " ; PWD=/home/"
                            + admin
                            + " ; USER=root ; COMMAND="
                            + pick(SUDO_COMMANDS);
            return syslog(at, AUTHPRIV, NOTICE, host, "sudo", pid, message);
        }
        if (kind < 92) {
            String message =
                    "checkpoint complete: wrote "
                            + (100 + random.nextInt(5000))
                            + " buffers ("
                            + random.nextInt(10)
                            + "."
                            + random.nextInt(10)
                            + "%); 0 WAL file(s) added, 0 removed, "
                            + random.nextInt(3)
                            + " recycled";
            return syslog(at, LOCAL0, INFO, "db-01", "postgres", pid, message);
        }
        if (kind < 97) {
            String message =
                    "/var usage at "
                            + (75 + random.nextInt(15))
                            + "% on "
                            + host
                            + ", above the 75% warning threshold";
            return syslog(at, DAEMON, WARNING, host, "diskmon", pid, message);
        }
        String message =
                "IPv4: martian source 10.20.0."
                        + random.nextInt(255)
                        + " from 10.20.0.1, on dev eth0";
        return syslog(at, KERN, INFO, host, "kernel", 0, message);
    }

    private static String syslog(
            Instant at, int facility, int severity, String host, String app, int pid, String msg) {
        String procId = pid > 0 ? Integer.toString(pid) : "-";
        return "<"
                + (facility * 8 + severity)
                + ">1 "
                + ISO_MILLIS.format(at)
                + " "
                + host
                + " "
                + app
                + " "
                + procId
                + " - - "
                + msg;
    }

    // --- JSON application events --------------------------------------------------------------

    private String jsonLine(Instant at) {
        Person person = pick(people);
        String action;
        String method;
        String path;
        int status;
        String outcome = "success";
        String level = "info";
        String message;
        int kind = random.nextInt(100);
        if (kind < 12) {
            action = "user.login";
            method = "POST";
            path = "/api/v1/session";
            if (random.nextInt(100) < 4) {
                // A mistyped password now and then; the next attempt usually succeeds.
                status = 401;
                outcome = "failure";
                level = "warn";
                message = "login failed for " + person.userName() + ": invalid password";
            } else {
                status = 200;
                message = "user " + person.userName() + " signed in";
            }
        } else if (kind < 20) {
            action = "user.logout";
            method = "DELETE";
            path = "/api/v1/session";
            status = 204;
            message = "user " + person.userName() + " signed out";
        } else if (kind < 60) {
            action = "product.view";
            method = "GET";
            path = "/api/v1/products/" + (1000 + random.nextInt(4000));
            status = 200;
            message = "product viewed";
        } else if (kind < 75) {
            action = "cart.update";
            method = "POST";
            path = "/api/v1/cart/items";
            status = 201;
            message = "item added to cart";
        } else if (kind < 85) {
            action = "order.create";
            method = "POST";
            path = "/api/v1/orders";
            status = 201;
            message = "order placed by " + person.userName();
        } else if (kind < 95) {
            action = "order.view";
            method = "GET";
            path = "/api/v1/orders/" + (100_000 + random.nextInt(900_000));
            status = 200;
            message = "order viewed";
        } else {
            action = "profile.update";
            method = "PATCH";
            path = "/api/v1/account/profile";
            status = 200;
            message = "profile updated by " + person.userName();
        }
        if (outcome.equals("success") && random.nextInt(1000) < 3) {
            status = 503;
            outcome = "failure";
            level = "error";
            message = "upstream timeout while handling " + action;
        }

        return "{\"@timestamp\":\""
                + ISO_MILLIS.format(at)
                + "\",\"id\":\""
                + uuid()
                + "\",\"log\":{\"level\":\""
                + level
                + "\"},\"message\":\""
                + json(message)
                + "\",\"host\":{\"name\":\""
                + pick(APP_HOSTS)
                + "\"},\"service\":{\"name\":\""
                + pick(APP_SERVICES)
                + "\"},\"event\":{\"action\":\""
                + action
                + "\",\"outcome\":\""
                + outcome
                + "\",\"duration\":"
                + (1_000_000L + random.nextLong(250_000_000L))
                + "},\"source\":{\"ip\":\""
                + person.ip()
                + "\",\"port\":"
                + (1024 + random.nextInt(64_000))
                + "},\"user\":{\"name\":\""
                + json(person.userName())
                + "\"},\"http\":{\"request\":{\"method\":\""
                + method
                + "\"},\"response\":{\"status_code\":"
                + status
                + ",\"body\":{\"bytes\":"
                + (status == 204 ? 0 : sizeAround(1_200))
                + "}}},\"url\":{\"original\":\""
                + json(path)
                + "\"},\"user_agent\":{\"original\":\""
                + json(person.userAgent())
                + "\"}}";
    }

    // --- shared helpers -----------------------------------------------------------------------

    private record Person(String userName, String ip, String userAgent) {}

    private Person newPerson(int index) {
        String name = pick(FIRST_NAMES) + "." + pick(LAST_NAMES) + (index % 7 == 0 ? index : "");
        return new Person(name, publicIp(), pick(BROWSER_AGENTS));
    }

    /**
     * A unicast address outside the private, loopback, link-local, CGNAT, multicast and
     * documentation ranges, so geo enrichment has something to resolve.
     */
    private String publicIp() {
        while (true) {
            int a = 1 + random.nextInt(223);
            int b = random.nextInt(256);
            boolean reserved =
                    a == 10
                            || a == 127
                            || a == 0
                            || (a == 100 && b >= 64 && b < 128)
                            || (a == 169 && b == 254)
                            || (a == 172 && b >= 16 && b < 32)
                            || (a == 192 && (b == 168 || b == 0))
                            || (a == 198 && (b == 18 || b == 19 || b == 51))
                            || (a == 203 && b == 0);
            if (!reserved) {
                return a + "." + b + "." + random.nextInt(256) + "." + (1 + random.nextInt(254));
            }
        }
    }

    /** Roughly log-normal around {@code median}, the usual shape of response sizes. */
    private long sizeAround(long median) {
        return Math.max(1, Math.round(median * Math.exp(0.6 * random.nextGaussian())));
    }

    private String uuid() {
        long most = (random.nextLong() & ~0xF000L) | 0x4000L;
        long least = (random.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(most, least).toString();
    }

    /** A stable, OpenSSH-shaped key fingerprint per user: 32 bytes, unpadded base64. */
    private static String fingerprint(String user) {
        byte[] digest = new byte[32];
        new SplittableRandom(user.hashCode()).nextBytes(digest);
        return Base64.getEncoder().withoutPadding().encodeToString(digest);
    }

    private static int uid(String user) {
        return 1000 + Math.floorMod(user.hashCode(), 50);
    }

    private <T> T pick(List<T> values) {
        return values.get(random.nextInt(values.size()));
    }

    private <T> T pick(T[] values) {
        return values[random.nextInt(values.length)];
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                out.append('\\').append(c);
            } else if (c < 0x20) {
                out.append(String.format("\\u%04x", (int) c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static Stream[] streamTable(Set<Stream> streams) {
        List<Stream> table = new ArrayList<>();
        for (Stream stream : Stream.values()) {
            if (streams.contains(stream)) {
                for (int i = 0; i < stream.weight; i++) {
                    table.add(stream);
                }
            }
        }
        return table.toArray(Stream[]::new);
    }

    private void writeManifest(Summary summary) throws IOException {
        StringBuilder files = new StringBuilder();
        summary.linesPerFile()
                .forEach(
                        (file, lines) -> {
                            if (!files.isEmpty()) {
                                files.append(",\n");
                            }
                            files.append("    \"").append(file).append("\": ").append(lines);
                        });
        String manifest =
                "{\n  \"seed\": "
                        + options.seed()
                        + ",\n  \"start\": \""
                        + options.start()
                        + "\",\n  \"end\": \""
                        + options.start().plus(options.span())
                        + "\",\n  \"events\": "
                        + summary.events()
                        + ",\n  \"files\": {\n"
                        + files
                        + "\n  }\n}\n";
        Files.writeString(options.outDir().resolve("manifest.json"), manifest);
    }

    /** Appends lines to {@code prefix-NNNN.ext}, opening the next file before one grows too big. */
    private static final class RollingWriter implements AutoCloseable {

        private final Path dir;
        private final Stream stream;
        private final long maxBytes;
        private final Map<String, Long> linesPerFile = new LinkedHashMap<>();
        private BufferedWriter out;
        private String currentName;
        private long currentBytes;
        private long totalLines;
        private int index;

        RollingWriter(Path dir, Stream stream, long maxBytes) {
            this.dir = dir;
            this.stream = stream;
            this.maxBytes = maxBytes;
        }

        void write(String line) {
            // Every character written is ASCII, so the string length is the byte count.
            long size = line.length() + 1L;
            try {
                if (out == null || currentBytes + size > maxBytes) {
                    open();
                }
                out.write(line);
                out.write('\n');
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            currentBytes += size;
            totalLines++;
            linesPerFile.merge(currentName, 1L, Long::sum);
        }

        private void open() throws IOException {
            close();
            index++;
            currentName =
                    String.format(
                            Locale.ROOT, "%s-%04d.%s", stream.prefix(), index, stream.extension());
            out =
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    Files.newOutputStream(dir.resolve(currentName)),
                                    StandardCharsets.UTF_8),
                            1 << 16);
            currentBytes = 0;
        }

        @Override
        public void close() throws IOException {
            if (out != null) {
                out.close();
                out = null;
            }
        }
    }
}
