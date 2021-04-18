package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

/**
 * Abstract class representing a {@link FileServerRequest} to read specific content of the file server.
 */
public abstract class FileServerReadRequest extends FileServerRequest {

    /**
     * Constructor for the {@link FileServerReadRequest} class.
     * @param   resourceLocation
     *          The location of the resources.
     */
    public FileServerReadRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public boolean coveredByPolicy(@NotNull RTreePolicy policy) {
        var generatedPolicy = new RTreePolicy(PolicyRight.READ, getResourceLocation());
        return policy.coversRTreePolicy(generatedPolicy);
    }
}
