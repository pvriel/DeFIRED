package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerWriteRequest} to delete a specific file with.
 */
public class FileServerDeleteFileRequest extends FileServerWriteRequest {

    /**
     * Constructor for the {@link FileServerDeleteFileRequest} class.
     *
     * @param resourceLocation The location of the specific file.
     */
    public FileServerDeleteFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "deleteFile";
    }
}
