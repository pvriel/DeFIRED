package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerDeleteFileRequest extends FileServerWriteRequest {

    public FileServerDeleteFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "deleteFile";
    }
}
