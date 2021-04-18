package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerReadRequest} to obtain the content of a specific file.
 */
public class FileServerReadFileRequest extends FileServerReadRequest {

    /**
     * Constructor for the {@link FileServerReadFileRequest} class.
     * @param   resourceLocation
     *          The location of the specific file.
     */
    public FileServerReadFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "readFile";
    }
}
