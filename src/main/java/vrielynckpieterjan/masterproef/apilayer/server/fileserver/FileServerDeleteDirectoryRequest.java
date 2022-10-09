package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerWriteRequest} to delete a directory with.
 */
public class FileServerDeleteDirectoryRequest extends FileServerWriteRequest {

    /**
     * Constructor for the {@link FileServerDeleteDirectoryRequest} class.
     *
     * @param resourceLocation The location of the specific directory to delete.
     */
    public FileServerDeleteDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "deleteDirectory";
    }
}
