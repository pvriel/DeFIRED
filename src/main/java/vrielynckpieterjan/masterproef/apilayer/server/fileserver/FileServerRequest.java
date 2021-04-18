package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

import java.io.Serializable;

/**
 * Abstract class representing a request for the file server part of the {@link vrielynckpieterjan.masterproef.apilayer.APILayer}.
 */
public abstract class FileServerRequest implements Serializable {

    private final String[] resourceLocation;

    /**
     * Constructor for the {@link FileServerRequest} class.
     * @param   resourceLocation
     *          The location of the specified resources.
     */
    protected FileServerRequest(@NotNull String[] resourceLocation) {
        this.resourceLocation = resourceLocation;
    }

    /**
     * Getter for the location of the specified resources.
     * @return  The location.
     */
    public String[] getResourceLocation() {
        return resourceLocation;
    }

    /**
     * Method to check if a user is allowed to perform a certain {@link FileServerRequest}, given the access
     * control {@link RTreePolicy} of that user for the file server.
     * @param   policy
     *          The {@link RTreePolicy} of the user.
     * @return  True if the user is allowed to execute the {@link FileServerRequest}; false otherwise.
     */
    public abstract boolean coveredByPolicy(@NotNull RTreePolicy policy);

    /**
     * Getter for the name of the {@link java.lang.reflect.Method} for the {@link FileServerInterface} realization
     * to execute this {@link FileServerRequest} with.
     * @return  The name of the {@link java.lang.reflect.Method}.
     */
    public abstract @NotNull String getFileServerInterfaceMethodName();
}
