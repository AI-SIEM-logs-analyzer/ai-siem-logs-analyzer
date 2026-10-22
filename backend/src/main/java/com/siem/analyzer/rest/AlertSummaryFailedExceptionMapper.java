package com.siem.analyzer.rest;

import com.siem.analyzer.service.AlertSummaryFailedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import org.jboss.logging.Logger;

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
