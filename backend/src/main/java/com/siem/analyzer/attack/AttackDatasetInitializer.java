package com.siem.analyzer.attack;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class AttackDatasetInitializer {

    private static final Logger LOG = Logger.getLogger(AttackDatasetInitializer.class);

    private final AttackDatasetService datasets;
    private final AppConfig appConfig;

    @Inject
    public AttackDatasetInitializer(AttackDatasetService datasets, AppConfig appConfig) {
        this.datasets = datasets;
        this.appConfig = appConfig;
    }

    void onStart(@Observes StartupEvent event) {
        if (!appConfig.attack().importOnStart()) {
            return;
        }
        try {
            if (datasets.importBundledIfNewer() == AttackDatasetService.Outcome.CURRENT) {
                LOG.debugf(
                        "MITRE ATT&CK %s or newer is already loaded",
                        appConfig.attack().bundledVersion());
            }
        } catch (RuntimeException e) {
            LOG.errorf(
                    e,
                    "Could not import the bundled MITRE ATT&CK dataset (%s). Alerts show bare"
                            + " technique IDs until an import succeeds; detection is unaffected.",
                    appConfig.attack().bundledResource());
        }
    }
}
