package vrielynckpieterjan.masterproef.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

public abstract class FileServerWriteRequest extends FileServerRequest {
    protected FileServerWriteRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }


    @Override
    public boolean coveredByPolicy(@NotNull RTreePolicy policy) {
        var generatedPolicy = new RTreePolicy(PolicyRight.WRITE, getResourceLocation());
        return policy.coversRTreePolicy(generatedPolicy);
    }
}
