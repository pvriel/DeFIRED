package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link FileServerWriteRequest} to write to a specific file.
 */
public class FileServerWriteFileRequest extends FileServerWriteRequest {

    private final byte[] newContent;

    /**
     * Constructor for the {@link FileServerWriteFileRequest} class.
     *
     * @param resourceLocation The location of the file.
     * @param newContent       The new content for the file.
     */
    public FileServerWriteFileRequest(@NotNull String[] resourceLocation,
                                      byte[] newContent) {
        super(resourceLocation);
        this.newContent = newContent;
    }

    /**
     * Getter for the new content of the file.
     *
     * @return The new content.
     */
    public byte[] getNewContent() {
        return newContent;
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "writeFile";
    }
}
