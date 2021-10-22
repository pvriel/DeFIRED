package anonymous.DFRDF.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerWriteRequest} to create a specific file with.
 */
public class FileServerCreateFileRequest extends FileServerWriteRequest {

    /**
     * Constructor for the {@link FileServerCreateFileRequest} with.
     * @param   resourceLocation
     *          The location of the specified file.
     */
    public FileServerCreateFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "createFile";
    }
}
