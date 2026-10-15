package com.siem.analyzer.attack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.zip.GZIPOutputStream;

/**
 * The hand-written ATT&CK bundle the suite runs on. The {@code %test} profile imports it at boot in
 * place of the 54 MB release, so every test sees these 10 techniques.
 */
public final class AttackFixtures {

    /** Classpath location of the fixture bundle. */
    public static final String RESOURCE = "/mitre/test-enterprise-attack.json";

    /**
     * Current Enterprise techniques in the fixture: revoked, deprecated and mobile ones excluded.
     */
    public static final int TECHNIQUE_COUNT = 10;

    private AttackFixtures() {}

    /** The fixture bundle's bytes. */
    public static byte[] bytes() {
        try (InputStream in = AttackFixtures.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(RESOURCE + " is not on the test classpath");
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** {@code bytes} gzipped, as an upload of a compressed bundle sends them. */
    public static byte[] gzip(byte[] bytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return out.toByteArray();
    }
}
