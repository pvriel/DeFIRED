package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerWriteFileRequest extends FileServerWriteRequest {

    private final byte[] newContent;

    public FileServerWriteFileRequest(@NotNull String[] resourceLocation,
                                      byte[] newContent) {
        super(resourceLocation);
        this.newContent = newContent;
    }

    public byte[] getNewContent() {
        return newContent;
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "writeFile";
    }
}
