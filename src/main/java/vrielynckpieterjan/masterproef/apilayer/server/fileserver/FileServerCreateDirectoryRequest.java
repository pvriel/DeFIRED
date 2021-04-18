package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerWriteRequest} to create a specific directory with.
 */
public class FileServerCreateDirectoryRequest extends FileServerWriteRequest {

    /**
     * Constructor for the {@link FileServerCreateDirectoryRequest} class.
     * @param   resourceLocation
     *          The path of the directory to create.
     */
    public FileServerCreateDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "createDirectory";
    }
}
