package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerReadRequest} to list the content of a directory.
 */
public class FileServerListDirectoryRequest extends FileServerReadRequest {

    /**
     * Constructor for the {@link FileServerListDirectoryRequest} class.
     *
     * @param resourceLocation The specified directory.
     */
    public FileServerListDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "listDirectory";
    }
}
