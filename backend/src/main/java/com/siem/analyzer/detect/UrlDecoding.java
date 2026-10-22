package com.siem.analyzer.detect;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

final class UrlDecoding {

    static final int MAX_PASSES = 3;

    private UrlDecoding() {}

    static String decode(String text) {
        if (text == null) {
            return null;
        }
        String decoded = text;
        for (int pass = 0; pass < MAX_PASSES; pass++) {
            String next = decodeOnce(decoded, pass == 0);
            if (next.equals(decoded)) {
                break;
            }
            decoded = next;
        }
        return decoded;
    }

    private static String decodeOnce(String text, boolean plusIsSpace) {
        if (text.indexOf('%') < 0 && (!plusIsSpace || text.indexOf('+') < 0)) {
            return text;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(text.length());
        int plain = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length() && isHex(text, i + 1) && isHex(text, i + 2)) {
                bytes.writeBytes(text.substring(plain, i).getBytes(StandardCharsets.UTF_8));
                bytes.write(Integer.parseInt(text, i + 1, i + 3, 16));
                i += 2;
                plain = i + 1;
            } else if (c == '+' && plusIsSpace) {
                bytes.writeBytes(text.substring(plain, i).getBytes(StandardCharsets.UTF_8));
                bytes.write(' ');
                plain = i + 1;
            }
        }
        bytes.writeBytes(text.substring(plain).getBytes(StandardCharsets.UTF_8));
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static boolean isHex(String text, int index) {
        char c = text.charAt(index);
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
