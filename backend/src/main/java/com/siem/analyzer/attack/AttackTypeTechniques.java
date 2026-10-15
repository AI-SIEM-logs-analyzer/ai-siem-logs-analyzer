package com.siem.analyzer.attack;

import com.siem.analyzer.domain.AttackType;
import java.util.Collections;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * The ATT&CK techniques an alert without a rule evidences, from the attack type a model gave it.
 *
 * <p>Every {@link AttackType} has an explicit entry, so a constant added there fails {@code
 * AttackTypeTechniquesTest} until someone decides what it maps to. A type the model uses when it
 * cannot name an attack ({@code ANOMALOUS_BEHAVIOUR}, {@code OTHER}) or finds none ({@code
 * BENIGN}), or one with no single technique behind it ({@code MALWARE}), maps to nothing rather
 * than to a guess. Base techniques where the type does not say which sub-technique: a model's
 * "brute force" is {@code T1110}, not a particular way of guessing.
 */
public final class AttackTypeTechniques {

    private static final Map<AttackType, List<String>> BY_TYPE = byType();

    private AttackTypeTechniques() {}

    private static Map<AttackType, List<String>> byType() {
        Map<AttackType, List<String>> byType = new EnumMap<>(AttackType.class);
        byType.put(AttackType.BRUTE_FORCE, List.of("T1110"));
        byType.put(AttackType.CREDENTIAL_STUFFING, List.of("T1110.004"));
        byType.put(AttackType.SQL_INJECTION, List.of("T1190"));
        byType.put(AttackType.PATH_TRAVERSAL, List.of("T1083", "T1190"));
        byType.put(AttackType.CROSS_SITE_SCRIPTING, List.of("T1189"));
        byType.put(AttackType.COMMAND_INJECTION, List.of("T1059", "T1190"));
        byType.put(AttackType.REMOTE_CODE_EXECUTION, List.of("T1059", "T1190"));
        byType.put(AttackType.RECONNAISSANCE, List.of("T1595"));
        byType.put(AttackType.DENIAL_OF_SERVICE, List.of("T1498", "T1499"));
        byType.put(AttackType.PRIVILEGE_ESCALATION, List.of("T1068"));
        byType.put(AttackType.DATA_EXFILTRATION, List.of("T1041"));
        byType.put(AttackType.MALWARE, List.of());
        byType.put(AttackType.ANOMALOUS_BEHAVIOUR, List.of());
        byType.put(AttackType.BENIGN, List.of());
        byType.put(AttackType.OTHER, List.of());
        return Collections.unmodifiableMap(byType);
    }

    /** The techniques of {@code type}, by ID; empty for a type that names no technique. */
    public static List<String> of(AttackType type) {
        List<String> ids = BY_TYPE.get(type);
        if (ids == null) {
            throw new IllegalStateException("no ATT&CK mapping for attack type " + type);
        }
        return ids;
    }

    /** Every technique some attack type maps to. */
    public static Set<String> allTechniqueIds() {
        Set<String> ids = new TreeSet<>();
        BY_TYPE.values().forEach(ids::addAll);
        return ids;
    }

    /** The attack types with at least one technique {@code accepts} takes. */
    public static Set<AttackType> matching(Predicate<String> accepts) {
        Set<AttackType> types = EnumSet.noneOf(AttackType.class);
        BY_TYPE.forEach(
                (type, ids) -> {
                    if (ids.stream().anyMatch(accepts)) {
                        types.add(type);
                    }
                });
        return types;
    }
}
