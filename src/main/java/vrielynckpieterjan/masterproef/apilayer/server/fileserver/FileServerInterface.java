package vrielynckpieterjan.masterproef.apilayer.server.fileserver;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;

/**
 * Interface representing the functionality of the file server part of the {@link vrielynckpieterjan.masterproef.apilayer.APILayer}.
 */
public interface FileServerInterface {

    /**
     * Method to create a directory.
     *
     * @param request The {@link FileServerCreateDirectoryRequest} instance.
     * @return True if the directory was successfully created, false otherwise.
     * @throws IllegalArgumentException If the file server can not create a directory at the specified location.
     * @throws IllegalStateException    If the file server can not create a directory at the specified location.
     * @throws IOException              If an IO-related problem occurred while creating the directory.
     */
    boolean createDirectory(@NotNull FileServerCreateDirectoryRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    /**
     * Method to list the files and directories within an existing directory.
     *
     * @param request The {@link FileServerListDirectoryRequest} instance.
     * @return The list as a String array.
     * @throws IllegalArgumentException If the server could not create a list for the specified location.
     * @throws IllegalStateException    If the server could not find the specified location.
     * @throws IOException              If an IO-related exception occurred while consulting the resources.
     */
    String[] listDirectory(@NotNull FileServerListDirectoryRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    /**
     * Method to delete a directory.
     *
     * @param request The {@link FileServerDeleteDirectoryRequest} instance.
     * @return True if the directory is deleted, false otherwise.
     * @throws IllegalArgumentException If the server could not delete a directory at the specified location.
     * @throws IllegalStateException    If the server could not find the specified location.
     * @throws IOException              If an IO-related exception occurred while consulting the resources.
     */
    boolean deleteDirectory(@NotNull FileServerDeleteDirectoryRequest request) throws IllegalArgumentException,
            IllegalStateException, IOException;

    /**
     * Method to create a file.
     *
     * @param request The {@link FileServerCreateFileRequest} instance.
     * @return True if the file was successfully created, false otherwise.
     * @throws IllegalArgumentException If the file server can not create a file at the specified location.
     * @throws IllegalStateException    If the file server can not create a file at the specified location.
     * @throws IOException              If an IO-related problem occurred while creating the file.
     */
    boolean createFile(@NotNull FileServerCreateFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    /**
     * Method to write to a file.
     *
     * @param request The {@link FileServerWriteFileRequest} instance.
     * @return True if the file was updated; false otherwise.
     * @throws IllegalArgumentException If the provided data could not be written to the file.
     * @throws IllegalStateException    If the {@link FileServerInterface} realization can not update the content of the file at the
     *                                  specified location.
     * @throws IOException              If the {@link FileServerInterface} can not update the content of the file due to an IO-related problem.
     */
    boolean writeFile(@NotNull FileServerWriteFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    /**
     * Method to get the content of a specified file.
     *
     * @param request The {@link FileServerReadFileRequest} instance.
     * @return The content of the specified file.
     * @throws IllegalArgumentException If the provided {@link FileServerReadFileRequest} instance could not be used to read an existing file.
     * @throws IllegalStateException    If the cloud storage service provider does not contain the specified file.
     * @throws IOException              If an IO-related problem occurred while consulting the content of the specified file.
     */
    byte[] readFile(@NotNull FileServerReadFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;

    /**
     * Method to delete a file.
     *
     * @param request The {@link FileServerDeleteFileRequest} instance.
     * @return True if the file is deleted, false otherwise.
     * @throws IllegalArgumentException If the server could not delete a file at the specified location.
     * @throws IllegalStateException    If the server could not find the specified location.
     * @throws IOException              If an IO-related exception occurred while consulting the resources.
     */
    boolean deleteFile(@NotNull FileServerDeleteFileRequest request) throws IllegalArgumentException, IllegalStateException,
            IOException;
}
