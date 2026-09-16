package com.siem.analyzer.rest;

import com.siem.analyzer.search.SearchUnavailableException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import org.jboss.logging.Logger;

/**
 * Answers 503 when the search engine could not be reached.
 *
 * <p>Deliberately not an empty 200. "Nothing matched" and "we could not look" are different
 * answers, and an analyst shown a clean board during an outage draws the wrong conclusion from it.
 * The message is generic on purpose — the engine's own error text can name hosts and indices.
 */
@Provider
public class SearchUnavailableExceptionMapper
        implements ExceptionMapper<SearchUnavailableException> {

    private static final Logger LOG = Logger.getLogger(SearchUnavailableExceptionMapper.class);

    @Override
    public Response toResponse(SearchUnavailableException exception) {
        LOG.errorf(exception, "Search request failed");
        return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                .entity(
                        Map.of(
                                "error",
                                "search_unavailable",
                                "message",
                                "The search index is unavailable. Events are still being"
                                        + " ingested and will appear once it recovers."))
                .build();
    }
}
