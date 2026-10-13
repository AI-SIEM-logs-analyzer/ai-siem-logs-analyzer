package com.siem.analyzer.attack;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.AttackDataset;
import com.siem.analyzer.domain.AttackTactic;
import com.siem.analyzer.domain.AttackTechnique;
import com.siem.analyzer.repo.AttackDatasetRepository;
import com.siem.analyzer.repo.AttackTacticRepository;
import com.siem.analyzer.repo.AttackTechniqueRepository;
import com.siem.analyzer.service.PayloadTooLargeException;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Loads a MITRE ATT&CK release into the dataset tables: the one bundled in the jar, or one an
 * administrator uploads.
 *
 * <p>The bundle is read before any transaction opens, so a 50 MB parse never holds database locks,
 * and a bundle the reader refuses changes nothing. Storing it is then one transaction that empties
 * and refills the four {@code attack_*} tables under an advisory lock: the dataset changes whole or
 * not at all, and replicas importing together take turns. {@code alert_rule_technique} is never
 * touched; rules keep their technique IDs across releases.
 */
@ApplicationScoped
public class AttackDatasetService {

    private static final Logger LOG = Logger.getLogger(AttackDatasetService.class);

    /** What a start-up import did. */
    public enum Outcome {
        /** The bundled release was stored. */
        IMPORTED,
        /** The stored release is the bundled one or newer; nothing was read. */
        CURRENT
    }

    private final AttackTacticRepository tactics;
    private final AttackTechniqueRepository techniques;
    private final AttackDatasetRepository datasets;
    private final AppConfig appConfig;

    @Inject
    public AttackDatasetService(
            AttackTacticRepository tactics,
            AttackTechniqueRepository techniques,
            AttackDatasetRepository datasets,
            AppConfig appConfig) {
        this.tactics = tactics;
        this.techniques = techniques;
        this.datasets = datasets;
        this.appConfig = appConfig;
    }

    /** The loaded release; empty until an import has succeeded. */
    public Optional<AttackDataset> current() {
        return QuarkusTransaction.requiringNew().call(datasets::current);
    }

    /**
     * Imports the bundled release when nothing is stored yet or the stored release is older. A
     * newer stored release, which only an upload can have put there, is left alone.
     */
    public Outcome importBundledIfNewer() {
        AppConfig.Attack config = appConfig.attack();
        Optional<String> stored = current().map(AttackDataset::getVersion);
        if (stored.isPresent() && !AttackVersions.isOlder(stored.get(), config.bundledVersion())) {
            return Outcome.CURRENT;
        }
        try (InputStream in = bundled(config.bundledResource())) {
            AttackDataset imported = store(AttackStixReader.read(in, config.maxBundleBytes()));
            LOG.infof(
                    "Imported MITRE ATT&CK %s (%d techniques) from %s, replacing %s",
                    imported.getVersion(),
                    imported.getTechniqueCount(),
                    config.bundledResource(),
                    stored.orElse("nothing"));
            return Outcome.IMPORTED;
        } catch (IOException e) {
            throw new UncheckedIOException("could not read " + config.bundledResource(), e);
        }
    }

    /**
     * Replaces the dataset with an uploaded bundle, gzipped or plain, whatever its release: an
     * administrator going back to an older one is making that call.
     *
     * @throws PayloadTooLargeException the body is over {@code app.attack.max-upload-bytes}
     * @throws InvalidAttackBundleException the body is not an ATT&CK bundle; nothing changes
     */
    public AttackDataset importUpload(InputStream body) {
        AppConfig.Attack config = appConfig.attack();
        byte[] bytes = readAtMost(body, config.maxUploadBytes());
        AttackDataset imported =
                store(
                        AttackStixReader.read(
                                new ByteArrayInputStream(bytes), config.maxBundleBytes()));
        LOG.infof(
                "Imported MITRE ATT&CK %s (%d techniques) from an upload",
                imported.getVersion(), imported.getTechniqueCount());
        return imported;
    }

    /**
     * Reads {@code in} whole, refusing it once it passes {@code limit} bytes. Reads one byte past
     * the limit, not the rest of the body, to tell "exactly the limit" from "over it".
     */
    static byte[] readAtMost(InputStream in, long limit) {
        try {
            byte[] bytes = in.readNBytes((int) Math.min(limit + 1, Integer.MAX_VALUE - 8));
            if (bytes.length > limit) {
                throw new PayloadTooLargeException(bytes.length, limit);
            }
            return bytes;
        } catch (IOException e) {
            throw new UncheckedIOException("could not read the uploaded bundle", e);
        }
    }

    private AttackDataset store(AttackBundle bundle) {
        return QuarkusTransaction.requiringNew()
                .call(
                        () -> {
                            datasets.lockForImport();
                            techniques.deleteDataset();
                            Map<String, AttackTactic> byId = new HashMap<>();
                            for (AttackBundle.Tactic tactic : bundle.tactics()) {
                                AttackTactic row =
                                        new AttackTactic(
                                                tactic.id(),
                                                tactic.name(),
                                                tactic.shortname(),
                                                tactic.url(),
                                                tactic.ordinal());
                                tactics.persist(row);
                                byId.put(tactic.id(), row);
                            }
                            for (AttackBundle.Technique technique : bundle.techniques()) {
                                List<AttackTactic> under =
                                        technique.tacticIds().stream().map(byId::get).toList();
                                techniques.persist(
                                        new AttackTechnique(
                                                technique.id(),
                                                technique.name(),
                                                technique.parentId(),
                                                technique.url(),
                                                under));
                            }
                            return recorded(bundle);
                        });
    }

    private AttackDataset recorded(AttackBundle bundle) {
        Instant now = Instant.now();
        int count = bundle.techniques().size();
        Optional<AttackDataset> existing = datasets.current();
        if (existing.isPresent()) {
            existing.get().replace(bundle.version(), bundle.sha256(), count, now);
            return existing.get();
        }
        AttackDataset row = new AttackDataset(bundle.version(), bundle.sha256(), count, now);
        datasets.persist(row);
        return row;
    }

    private static InputStream bundled(String resource) {
        InputStream in =
                Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        if (in == null) {
            throw new IllegalStateException(
                    "the bundled ATT&CK dataset is not on the classpath: " + resource);
        }
        return in;
    }
}
