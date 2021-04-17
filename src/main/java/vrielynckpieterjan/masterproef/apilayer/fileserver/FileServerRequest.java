package vrielynckpieterjan.masterproef.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

import java.io.Serializable;

public abstract class FileServerRequest implements Serializable {

    private final String[] resourceLocation;

    protected FileServerRequest(@NotNull String[] resourceLocation) {
        this.resourceLocation = resourceLocation;
    }

    public String[] getResourceLocation() {
        return resourceLocation;
    }

    public abstract boolean coveredByPolicy(@NotNull RTreePolicy policy);

    public abstract @NotNull String getFileServerInterfaceMethodName();
}
