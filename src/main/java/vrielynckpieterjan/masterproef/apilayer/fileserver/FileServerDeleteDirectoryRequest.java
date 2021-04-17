package vrielynckpieterjan.masterproef.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerDeleteDirectoryRequest extends FileServerWriteRequest {
    public FileServerDeleteDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "deleteDirectory";
    }
}
