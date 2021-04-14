package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

public class FileServerReadFileRequest extends FileServerReadRequest {
    public FileServerReadFileRequest(@NotNull String[] resourceLocation) {
        super(resourceLocation);
    }

    @Override
    public @NotNull String getFileServerInterfaceMethodName() {
        return "readFile";
    }
}
