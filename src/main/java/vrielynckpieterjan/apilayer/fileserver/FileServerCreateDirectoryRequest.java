package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerCreateDirectoryRequest extends FileServerWriteRequest {

    public FileServerCreateDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "createDirectory";
    }
}
