package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;

public abstract class FileServerReadRequest extends FileServerRequest {
    public FileServerReadRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public boolean coveredByPolicy(@NotNull RTreePolicy policy) {
        var generatedPolicy = new RTreePolicy(PolicyRight.READ, getResourceLocation());
        return policy.coversRTreePolicy(generatedPolicy);
    }
}
