package vrielynckpieterjan.apilayer.fileserver;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;

public interface FileServerInterface {

    boolean createDirectory(@NotNull FileServerCreateDirectoryRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    String[] listDirectory(@NotNull FileServerListDirectoryRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    boolean deleteDirectory(@NotNull FileServerDeleteDirectoryRequest request) throws IllegalArgumentException,
            IllegalStateException, IOException;

    boolean createFile(@NotNull FileServerCreateFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    boolean writeFile(@NotNull FileServerWriteFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    byte[] readFile(@NotNull FileServerReadFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    boolean deleteFile(@NotNull FileServerDeleteFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;
}
