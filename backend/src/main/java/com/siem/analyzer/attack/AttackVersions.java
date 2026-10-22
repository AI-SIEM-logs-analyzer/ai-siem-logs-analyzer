package com.siem.analyzer.attack;

final class AttackVersions {

    private AttackVersions() {}

    static boolean isOlder(String stored, String candidate) {
        return compare(stored, candidate) < 0;
    }

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
