package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerCreateFileRequest extends FileServerWriteRequest {
    public FileServerCreateFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "createFile";
    }
}
