package com.siem.analyzer.attack;

/** Compares ATT&CK releases ({@code 9.0}, {@code 18.1}, {@code 19.2}) as dotted numbers. */
final class AttackVersions {

    private AttackVersions() {}

    /** Whether release {@code stored} is older than {@code candidate}. */
    static boolean isOlder(String stored, String candidate) {
        return compare(stored, candidate) < 0;
    }

    /**
     * Compares part by part as numbers, so {@code 19.2 < 19.10}. A missing part counts as 0, and so
     * does a part that is not a number: a malformed release sorts low, and the bundled one replaces
     * it.
     */
    static int compare(String left, String right) {
        String[] a = left.split("\\.");
        String[] b = right.split("\\.");
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            int order = Integer.compare(part(a, i), part(b, i));
            if (order != 0) {
                return order;
            }
        }
        return 0;
    }

    private static int part(String[] parts, int index) {
        if (index >= parts.length) {
            return 0;
        }
        try {
            return Integer.parseInt(parts[index].strip());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
