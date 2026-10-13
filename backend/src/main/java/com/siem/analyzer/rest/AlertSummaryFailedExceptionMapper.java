package com.siem.analyzer.rest;

import com.siem.analyzer.service.AlertSummaryFailedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import org.jboss.logging.Logger;

/**
 * Answers 502 when the AI provider gave no usable summary.
 *
 * <p>The provider is the upstream that failed, not this server. The message is generic on purpose:
 * a provider's error text can carry request ids, account details or fragments of the prompt, which
 * hold log data. The cause is logged instead. An answer dropped by the grounding check gets a
 * sentence of its own, so the analyst knows the provider worked and the model made things up.
 */
@Provider
public class AlertSummaryFailedExceptionMapper
        implements ExceptionMapper<AlertSummaryFailedException> {

    private static final Logger LOG = Logger.getLogger(AlertSummaryFailedExceptionMapper.class);

    @Override
    public Response toResponse(AlertSummaryFailedException exception) {
        LOG.warn(exception.getMessage());
        return Response.status(Response.Status.BAD_GATEWAY)
                .entity(
                        Map.of(
                                "error",
                                "ai_summary_failed",
                                "message",
                                exception.isUngrounded()
                                        ? "The model's answer cited details this alert does not"
                                                + " contain, so it was discarded. The alert is"
                                                + " unchanged; try again."
                                        : "The AI provider could not summarise this alert. The"
                                                + " alert is unchanged; try again later."))
                .build();
    }
}
