package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerListDirectoryRequest extends FileServerReadRequest {

    public FileServerListDirectoryRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "listDirectory";
    }
}
