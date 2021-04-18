package vrielynckpieterjan.masterproef.apilayer;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.apilayer.server.fileserver.*;
import vrielynckpieterjan.masterproef.apilayer.server.SimpleAPILayerServer;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

import java.io.*;
import java.nio.file.Path;
import java.util.*;

/**
 * Class representing the API layer of the framework.
 */
public class APILayer extends Thread implements Closeable, FileServerInterface {

    private final SimpleAPILayerServer server;
    private final Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers =
            Collections.synchronizedMap(new HashMap<>());
    private final File resourcesLocation;

    /**
     * Constructor for the {@link APILayer} class.
     * @param   amountOfThreads
     *          The amount of simultaneous external connections the {@link SimpleAPILayerServer} of this instance
     *          can handle.
     * @param   port
     *          The port on which the {@link SimpleAPILayerServer} can run.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult.
     * @param   resourcesLocation
     *          The {@link File} location at which the resources of the cloud storage service provider may be stored.
     * @throws  IOException
     *          If the provided resourcesLocation argument can't be used to store the service provider's resources.
     */
    public APILayer(int amountOfThreads, int port, @NotNull StorageLayer storageLayer,
                    @NotNull File resourcesLocation) throws IOException {
        server = new SimpleAPILayerServer(amountOfThreads, port, storageLayer, registeredUsers, revocationSecretsAcceptedPolicies,
                currentStorageElementIdentifiers, this);

        resourcesLocation.mkdirs();
        if (!resourcesLocation.canWrite()) throw new IllegalStateException("Can not write to the provided path.");
        this.resourcesLocation = resourcesLocation;
    }

    /**
     * Method to internally register a user as a registered user of the cloud storage service provider.
     * @param   userIdentifiers
     *          The {@link PrivateEntityIdentifier} and {@link PublicEntityIdentifier} instances of the new user.
     * @apiNote
     *          This method does not generate or store a namespace attestation for the {@link StorageLayer}.
     */
    public void registerUser(@NotNull Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userIdentifiers) {
        registeredUsers.put(userIdentifiers.getRight(), userIdentifiers.getLeft());
        currentStorageElementIdentifiers.put(userIdentifiers.getRight(),
                new StorageElementIdentifier(userIdentifiers.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation()));
    }

    @Override
    public void run() {
        server.start();
    }

    @Override
    public void close() {
        server.interrupt();
    }

    @Override
    public boolean createDirectory(@NotNull FileServerCreateDirectoryRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var dir = obtainFileInstanceFor(request);
        return dir.mkdirs();
    }

    @Override
    public String[] listDirectory(@NotNull FileServerListDirectoryRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var dir = obtainFileInstanceFor(request);
        return dir.list();
    }

    @Override
    public boolean deleteDirectory(@NotNull FileServerDeleteDirectoryRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var dir = obtainFileInstanceFor(request);
        if (dir.isFile()) throw new IllegalArgumentException("Specified resource is a file.");
        deleteContentDirectory(dir);
        return dir.delete();
    }

    /**
     * Method to recursively delete the content of a given {@link File} directory.
     * @param   directory
     *          The directory.
     */
    private void deleteContentDirectory(@NotNull File directory) {
        for (var fileOrDir: directory.listFiles()) {
            if (fileOrDir.isDirectory())
                deleteContentDirectory(fileOrDir);
            fileOrDir.delete();
        }
    }

    @Override
    public boolean createFile(@NotNull FileServerCreateFileRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var file = obtainFileInstanceFor(request);
        return file.createNewFile();
    }

    @Override
    public boolean writeFile(@NotNull FileServerWriteFileRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var file = obtainFileInstanceFor(request);
        var outputStream = new FileOutputStream(file);
        try {
            outputStream.write(request.getNewContent());
            outputStream.close();
            return true;
        } catch (IOException e) {
            outputStream.close();
            return false;
        }
    }

    @Override
    public byte[] readFile(@NotNull FileServerReadFileRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var file = obtainFileInstanceFor(request);
        var inputStream = new FileInputStream(file);
        try {
            byte[] bytes = inputStream.readAllBytes();
            inputStream.close();
            return bytes;
        } catch (IOException e) {
            inputStream.close();
            throw e;
        }
    }

    @Override
    public boolean deleteFile(@NotNull FileServerDeleteFileRequest request) throws IllegalArgumentException, IllegalStateException, IOException {
        var file = obtainFileInstanceFor(request);
        return file.delete();
    }

    /**
     * Method to convert a {@link FileServerRequest} to a {@link File} instance for the specified resources.
     * @param   fileServerRequest
     *          The {@link FileServerRequest} instance.
     * @return  The converted {@link File}.
     * @throws  IllegalArgumentException
     *          If the provided {@link FileServerRequest} does not point to resources that are actually
     *          stored by the cloud storage service provider.
     */
    private @NotNull File obtainFileInstanceFor(@NotNull FileServerRequest fileServerRequest)
        throws IllegalArgumentException {
        var path = Path.of(resourcesLocation.getAbsolutePath(), fileServerRequest.getResourceLocation());
        return path.toFile();
    }

}
