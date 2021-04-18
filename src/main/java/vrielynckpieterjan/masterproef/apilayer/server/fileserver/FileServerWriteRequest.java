package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

/**
 * Abstract class representing a {@link FileServerRequest} to write to specific resources.
 */
public abstract class FileServerWriteRequest extends FileServerRequest {

    /**
     * Constructor for the {@link FileServerWriteRequest} class.
     * @param   resourceLocation
     *          The location of the specific resources.
     */
    protected FileServerWriteRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }


    @Override
    public boolean coveredByPolicy(@NotNull RTreePolicy policy) {
        var generatedPolicy = new RTreePolicy(PolicyRight.WRITE, getResourceLocation());
        return policy.coversRTreePolicy(generatedPolicy);
    }
}
