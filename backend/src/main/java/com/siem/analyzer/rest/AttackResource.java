package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AttackCatalog;
import com.siem.analyzer.attack.AttackDatasetService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.io.InputStream;
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The MITRE ATT&CK Enterprise tactics and techniques alerts are mapped to, and the dataset they
 * come from.
 *
 * <p>Reading is open to every signed-in role, like the alerts the catalogue names. Replacing the
 * dataset is for administrators: it changes what every alert in the system is said to be.
 */
@Path("/api/attack")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "MITRE ATT&CK", description = "The ATT&CK techniques and tactics alerts are mapped to")
public class AttackResource {

    private final AttackCatalog catalog;
    private final AttackDatasetService datasets;

    @Inject
    public AttackResource(AttackCatalog catalog, AttackDatasetService datasets) {
        this.catalog = catalog;
        this.datasets = datasets;
    }

    @GET
    @Path("/tactics")
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(operationId = "listAttackTactics", summary = "List the tactics in matrix order")
    @APIResponse(responseCode = "200", description = "Every tactic in the loaded dataset")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow reading")
    public List<AttackTacticResponse> tactics() {
        return catalog.tactics().stream().map(AttackTacticResponse::from).toList();
    }

    @GET
    @Path("/techniques")
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(
            operationId = "listAttackTechniques",
            summary = "List techniques",
            description =
                    "Every technique in the loaded dataset, by ID; with inUse=true, only those an"
                            + " alert can name: mapped by an enabled rule or by the AI attack-type"
                            + " fallback. An ID the dataset does not know comes without a name.")
    @APIResponse(responseCode = "200", description = "The techniques")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow reading")
    public List<AttackTechniqueResponse> techniques(
            @Parameter(description = "Only the techniques an alert can name")
                    @QueryParam("inUse")
                    @DefaultValue("false")
                    boolean inUse) {
        return (inUse ? catalog.techniquesInUse() : catalog.techniques())
                .stream().map(AttackTechniqueResponse::from).toList();
    }

    @GET
    @Path("/dataset")
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(operationId = "getAttackDataset", summary = "Which ATT&CK release is loaded")
    @APIResponse(responseCode = "200", description = "The loaded release")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow reading")
    @APIResponse(responseCode = "404", description = "No release has been imported")
    public AttackDatasetResponse dataset() {
        return datasets.current()
                .map(AttackDatasetResponse::from)
                .orElseThrow(() -> new NotFoundException("no ATT&CK dataset has been imported"));
    }

    @POST
    @Path("/dataset")
    @RolesAllowed("ADMIN")
    @Consumes({MediaType.APPLICATION_JSON, "application/gzip", MediaType.APPLICATION_OCTET_STREAM})
    @Operation(
            operationId = "importAttackDataset",
            summary = "Replace the ATT&CK dataset",
            description =
                    "Takes an Enterprise ATT&CK STIX 2.1 bundle (enterprise-attack-<version>.json"
                            + " from mitre-attack/attack-stix-data), plain or gzipped, and replaces"
                            + " the loaded tactics and techniques with it whatever its version."
                            + " Rules keep their technique IDs. Gzip is recommended: the release"
                            + " JSON is close to the upload limit.")
    @APIResponse(responseCode = "200", description = "The release now loaded")
    @APIResponse(responseCode = "400", description = "Not an ATT&CK bundle; nothing changed")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "Only an administrator may import")
    @APIResponse(responseCode = "413", description = "Larger than app.attack.max-upload-bytes")
    public AttackDatasetResponse importDataset(InputStream body) {
        return AttackDatasetResponse.from(datasets.importUpload(body));
    }
}
