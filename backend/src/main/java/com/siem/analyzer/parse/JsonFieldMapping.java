package com.siem.analyzer.parse;

import com.siem.analyzer.config.AppConfig;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Where {@link JsonLogParser} looks for each standard field of a {@link
 * com.siem.analyzer.domain.NormalizedEvent}.
 *
 * <p>Every field has an ordered list of candidate paths, and the first one that holds a usable
 * value wins. A path is a dot-separated list of keys, {@code http.request.method}. It matches the
 * nested objects {@code {"http":{"request":{"method":...}}}} and equally the flat key {@code
 * {"http.request.method":...}} or any mix of the two, because shippers disagree on which to write:
 * Filebeat nests ECS fields, and most application loggers flatten them. A key that itself contains
 * a dot is therefore reachable without an escape syntax.
 *
 * <p>The defaults cover Elastic Common Schema, nginx {@code log_format ... escape=json} with the
 * variable names as keys, pino and bunyan, Python's JSON loggers, the Docker {@code json-file}
 * driver and a few generic names. They are strings so that {@link AppConfig} can use them as its
 * {@code @WithDefault} values, which keeps the unit-tested defaults and the deployed ones from
 * drifting apart. An empty list turns a field off.
 *
 * <p>Instances are immutable.
 */
public final class JsonFieldMapping {

    /** The standard fields a JSON line can fill; the event's format and raw line are not mapped. */
    public enum Field {
        TIMESTAMP,
        HOST,
        SRC_IP,
        SRC_PORT,
        USER,
        METHOD,
        PATH,
        PROTOCOL,
        STATUS,
        BYTES,
        REFERRER,
        USER_AGENT,
        SEVERITY,
        MESSAGE
    }

    // time_local is nginx's $time_local; eventTime is CloudTrail's.
    public static final String DEFAULT_TIMESTAMP =
            "@timestamp,timestamp,time,ts,datetime,date,eventTime,time_local";
    public static final String DEFAULT_HOST = "host.name,hostname,host";
    public static final String DEFAULT_SRC_IP =
            "source.ip,client.ip,src_ip,client_ip,clientip,remote_addr,sourceIPAddress,ip";
    public static final String DEFAULT_SRC_PORT = "source.port,client.port,src_port,remote_port";
    public static final String DEFAULT_USER = "user.name,user_name,username,user,remote_user";
    public static final String DEFAULT_METHOD = "http.request.method,request_method,method";
    // url.original before url.path: the event's path keeps the query string when the log has one.
    public static final String DEFAULT_PATH = "url.original,url.path,request_uri,uri,path";
    public static final String DEFAULT_PROTOCOL = "server_protocol,protocol,http.version";
    public static final String DEFAULT_STATUS = "http.response.status_code,status_code,status";
    public static final String DEFAULT_BYTES =
            "http.response.body.bytes,body_bytes_sent,bytes_sent,bytes";
    public static final String DEFAULT_REFERRER =
            "http.request.referrer,http_referer,referrer,referer";
    public static final String DEFAULT_USER_AGENT =
            "user_agent.original,http_user_agent,user_agent,userAgent";
    // levelname is Python's; loglevel is common in hand-rolled Java layouts.
    public static final String DEFAULT_SEVERITY = "log.level,level,severity,levelname,loglevel";
    // log is the Docker json-file driver's message key. In ECS it is an object, which a text
    // field never matches, so the two do not collide.
    public static final String DEFAULT_MESSAGE = "message,msg,log";

    private static final JsonFieldMapping DEFAULTS =
            new JsonFieldMapping(
                    new EnumMap<>(
                            Map.ofEntries(
                                    Map.entry(Field.TIMESTAMP, split(DEFAULT_TIMESTAMP)),
                                    Map.entry(Field.HOST, split(DEFAULT_HOST)),
                                    Map.entry(Field.SRC_IP, split(DEFAULT_SRC_IP)),
                                    Map.entry(Field.SRC_PORT, split(DEFAULT_SRC_PORT)),
                                    Map.entry(Field.USER, split(DEFAULT_USER)),
                                    Map.entry(Field.METHOD, split(DEFAULT_METHOD)),
                                    Map.entry(Field.PATH, split(DEFAULT_PATH)),
                                    Map.entry(Field.PROTOCOL, split(DEFAULT_PROTOCOL)),
                                    Map.entry(Field.STATUS, split(DEFAULT_STATUS)),
                                    Map.entry(Field.BYTES, split(DEFAULT_BYTES)),
                                    Map.entry(Field.REFERRER, split(DEFAULT_REFERRER)),
                                    Map.entry(Field.USER_AGENT, split(DEFAULT_USER_AGENT)),
                                    Map.entry(Field.SEVERITY, split(DEFAULT_SEVERITY)),
                                    Map.entry(Field.MESSAGE, split(DEFAULT_MESSAGE)))));

    private final Map<Field, List<String>> paths;

    private JsonFieldMapping(Map<Field, List<String>> paths) {
        EnumMap<Field, List<String>> copy = new EnumMap<>(Field.class);
        for (Field field : Field.values()) {
            List<String> candidates = paths.get(field);
            copy.put(field, candidates == null ? List.of() : validate(field, candidates));
        }
        this.paths = Collections.unmodifiableMap(copy);
    }

    /** The built-in mapping, the same one {@link AppConfig} deploys when nothing is overridden. */
    public static JsonFieldMapping defaults() {
        return DEFAULTS;
    }

    /**
     * Reads the mapping from configuration.
     *
     * @throws IllegalArgumentException a configured path is blank or has an empty segment
     */
    public static JsonFieldMapping from(AppConfig.Parse.Json.Fields fields) {
        Map<Field, List<String>> paths = new EnumMap<>(Field.class);
        paths.put(Field.TIMESTAMP, fields.timestamp());
        paths.put(Field.HOST, fields.host());
        paths.put(Field.SRC_IP, fields.srcIp());
        paths.put(Field.SRC_PORT, fields.srcPort());
        paths.put(Field.USER, fields.user());
        paths.put(Field.METHOD, fields.method());
        paths.put(Field.PATH, fields.path());
        paths.put(Field.PROTOCOL, fields.protocol());
        paths.put(Field.STATUS, fields.status());
        paths.put(Field.BYTES, fields.bytes());
        paths.put(Field.REFERRER, fields.referrer());
        paths.put(Field.USER_AGENT, fields.userAgent());
        paths.put(Field.SEVERITY, fields.severity());
        paths.put(Field.MESSAGE, fields.message());
        return new JsonFieldMapping(paths);
    }

    /** The candidate paths for one field, in the order they are tried; never {@code null}. */
    public List<String> paths(Field field) {
        return paths.get(Objects.requireNonNull(field, "field"));
    }

    /**
     * Returns a copy with the candidates for one field replaced.
     *
     * @throws IllegalArgumentException a path is blank or has an empty segment
     */
    public JsonFieldMapping withField(Field field, List<String> candidates) {
        Map<Field, List<String>> copy = new EnumMap<>(paths);
        copy.put(Objects.requireNonNull(field, "field"), candidates);
        return new JsonFieldMapping(copy);
    }

    private static List<String> validate(Field field, List<String> candidates) {
        for (String path : candidates) {
            // "a..b" or a leading or trailing dot would silently never match anything, which is
            // the kind of typo that should stop the application from starting, not lose a field.
            if (path == null
                    || path.isBlank()
                    || path.startsWith(".")
                    || path.endsWith(".")
                    || path.contains("..")) {
                throw new IllegalArgumentException(
                        "Invalid JSON path for " + field + ": '" + path + "'");
            }
        }
        return List.copyOf(candidates);
    }

    private static List<String> split(String paths) {
        return List.of(paths.split(","));
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof JsonFieldMapping mapping && paths.equals(mapping.paths);
    }

    @Override
    public int hashCode() {
        return paths.hashCode();
    }

    @Override
    public String toString() {
        return "JsonFieldMapping" + paths;
    }
}
