package com.siem.analyzer.attack;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

public final class AttackStixReader {

    public static final Pattern TECHNIQUE_ID = Pattern.compile("T\\d{4}(\\.\\d{3})?");

    public static final Pattern TACTIC_ID = Pattern.compile("TA\\d{4}");

    private static final String DOMAIN = "enterprise-attack";
    private static final String SOURCE = "mitre-attack";

    private static final String URL_PREFIX = "https://attack.mitre.org/";

    private static final ObjectMapper JSON = new ObjectMapper();

    private AttackStixReader() {}

    public static AttackBundle read(InputStream in, long maxJsonBytes) {
        MessageDigest digest = sha256();
        try {
            BufferedInputStream buffered = new BufferedInputStream(in);
            InputStream json = isGzip(buffered) ? new GZIPInputStream(buffered) : buffered;
            InputStream hashed =
                    new DigestInputStream(new BoundedInputStream(json, maxJsonBytes), digest);
            Collected collected = new Collected();
            try (JsonParser parser = JSON.createParser(hashed)) {
                readBundle(parser, collected);

                hashed.transferTo(OutputStream.nullOutputStream());
            }
            return collected.toBundle(HexFormat.of().formatHex(digest.digest()));
        } catch (BoundedInputStream.TooLarge e) {
            throw new InvalidAttackBundleException(
                    "the bundle is larger than " + e.limit() + " bytes once decompressed", e);
        } catch (IOException e) {
            throw new InvalidAttackBundleException(
                    "the bundle is not valid JSON or gzip: " + e.getMessage(), e);
        }
    }

    private static void readBundle(JsonParser parser, Collected collected) throws IOException {
        if (parser.nextToken() != JsonToken.START_OBJECT) {
            throw invalid("the bundle is not a JSON object");
        }
        String type = null;
        boolean sawObjects = false;
        while (parser.nextToken() == JsonToken.FIELD_NAME) {
            String field = parser.currentName();
            JsonToken value = parser.nextToken();
            if ("type".equals(field)) {
                type = value == JsonToken.VALUE_STRING ? parser.getText() : null;
            } else if ("objects".equals(field)) {
                if (value != JsonToken.START_ARRAY) {
                    throw invalid("'objects' is not an array");
                }
                sawObjects = true;
                while (parser.nextToken() == JsonToken.START_OBJECT) {
                    JsonNode object = JSON.readTree(parser);
                    collected.add(object);
                }
                if (parser.currentToken() != JsonToken.END_ARRAY) {
                    throw invalid("'objects' holds something other than objects");
                }
            } else {
                parser.skipChildren();
            }
        }
        if (!"bundle".equals(type)) {
            throw invalid("the document is not a STIX bundle");
        }
        if (!sawObjects) {
            throw invalid("the bundle has no 'objects'");
        }
    }

    private static final class Collected {

        private String version;
        private final List<String> matrixTactics = new ArrayList<>();
        private final Map<String, PendingTactic> tacticsByStixId = new LinkedHashMap<>();
        private final List<PendingTechnique> techniques = new ArrayList<>();

        void add(JsonNode object) {
            switch (object.path("type").asText("")) {
                case "x-mitre-collection" -> version = text(object, "x_mitre_version");
                case "x-mitre-matrix" -> {
                    if (current(object)) {
                        object.path("tactic_refs").forEach(ref -> matrixTactics.add(ref.asText()));
                    }
                }
                case "x-mitre-tactic" -> {
                    if (current(object)) {
                        PendingTactic tactic = PendingTactic.of(object);
                        tacticsByStixId.put(tactic.stixId(), tactic);
                    }
                }
                case "attack-pattern" -> {
                    if (current(object)) {
                        techniques.add(PendingTechnique.of(object));
                    }
                }
                default -> {}
            }
        }

        AttackBundle toBundle(String sha256) {
            if (version == null) {
                throw invalid("the bundle has no x-mitre-collection with a version");
            }
            if (tacticsByStixId.isEmpty()) {
                throw invalid("the bundle holds no current Enterprise tactics");
            }
            if (techniques.isEmpty()) {
                throw invalid("the bundle holds no current Enterprise techniques");
            }

            List<PendingTactic> ordered = new ArrayList<>(tacticsByStixId.values());
            ordered.sort(
                    Comparator.comparingInt((PendingTactic tactic) -> position(tactic.stixId()))
                            .thenComparing(PendingTactic::id));
            List<AttackBundle.Tactic> tactics = new ArrayList<>();
            Map<String, String> idByShortname = new HashMap<>();
            Set<String> tacticIds = new HashSet<>();
            for (PendingTactic tactic : ordered) {
                if (!TACTIC_ID.matcher(tactic.id()).matches()) {
                    throw invalid("malformed tactic ID " + tactic.id());
                }
                if (!tacticIds.add(tactic.id())) {
                    throw invalid("tactic " + tactic.id() + " appears twice");
                }
                idByShortname.put(tactic.shortname(), tactic.id());
                tactics.add(
                        new AttackBundle.Tactic(
                                tactic.id(),
                                tactic.name(),
                                tactic.shortname(),
                                tactic.url(),
                                tactics.size() + 1));
            }

            Map<String, AttackBundle.Technique> byId = new TreeMap<>();
            for (PendingTechnique technique : techniques) {
                String id = technique.id();
                if (!TECHNIQUE_ID.matcher(id).matches()) {
                    throw invalid("malformed technique ID " + id);
                }
                int dot = id.indexOf('.');
                List<String> under =
                        technique.phases().stream()
                                .map(idByShortname::get)
                                .filter(Objects::nonNull)
                                .distinct()
                                .toList();
                AttackBundle.Technique kept =
                        new AttackBundle.Technique(
                                id,
                                technique.name(),
                                dot < 0 ? null : id.substring(0, dot),
                                technique.url(),
                                under);
                if (byId.putIfAbsent(id, kept) != null) {
                    throw invalid("technique " + id + " appears twice");
                }
            }
            return new AttackBundle(version, sha256, tactics, List.copyOf(byId.values()));
        }

        private int position(String stixId) {
            int index = matrixTactics.indexOf(stixId);
            return index < 0 ? Integer.MAX_VALUE : index;
        }
    }

    private record PendingTactic(
            String stixId, String id, String name, String shortname, String url) {

        static PendingTactic of(JsonNode object) {
            Reference reference = reference(object);
            return new PendingTactic(
                    required(object, "id"),
                    reference.id(),
                    required(object, "name"),
                    required(object, "x_mitre_shortname"),
                    reference.url());
        }
    }

    private record PendingTechnique(String id, String name, String url, List<String> phases) {

        static PendingTechnique of(JsonNode object) {
            Reference reference = reference(object);
            List<String> phases = new ArrayList<>();
            for (JsonNode phase : object.path("kill_chain_phases")) {
                String name = text(phase, "phase_name");
                if (SOURCE.equals(phase.path("kill_chain_name").asText()) && name != null) {
                    phases.add(name);
                }
            }
            return new PendingTechnique(
                    reference.id(), required(object, "name"), reference.url(), phases);
        }
    }

    private record Reference(String id, String url) {}

    private static Reference reference(JsonNode object) {
        for (JsonNode reference : object.path("external_references")) {
            String id = text(reference, "external_id");
            if (SOURCE.equals(reference.path("source_name").asText()) && id != null) {
                String url = text(reference, "url");
                return new Reference(id, url != null && url.startsWith(URL_PREFIX) ? url : null);
            }
        }
        throw invalid(
                "'" + object.path("name").asText("(unnamed)") + "' has no mitre-attack reference");
    }

    private static boolean current(JsonNode object) {
        if (object.path("revoked").asBoolean(false)
                || object.path("x_mitre_deprecated").asBoolean(false)) {
            return false;
        }
        JsonNode domains = object.get("x_mitre_domains");
        if (domains == null || !domains.isArray()) {
            return true;
        }
        for (JsonNode domain : domains) {
            if (DOMAIN.equals(domain.asText())) {
                return true;
            }
        }
        return false;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isValueNode() || value.asText().isBlank()) {
            return null;
        }
        return value.asText().strip();
    }

    private static String required(JsonNode node, String field) {
        String value = text(node, field);
        if (value == null) {
            throw invalid("'" + node.path("name").asText("(unnamed)") + "' has no '" + field + "'");
        }
        return value;
    }

    private static boolean isGzip(BufferedInputStream in) throws IOException {
        in.mark(2);
        int first = in.read();
        int second = in.read();
        in.reset();
        return first == 0x1f && second == 0x8b;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JVM ships SHA-256", e);
        }
    }

    private static InvalidAttackBundleException invalid(String reason) {
        return new InvalidAttackBundleException(reason);
    }
}
