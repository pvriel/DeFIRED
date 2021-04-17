package vrielynckpieterjan.masterproef.apilayer;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.apilayer.fileserver.*;
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

public class APILayer extends Thread implements Closeable, FileServerInterface {

    private final SimpleAPILayerServer server;
    private final Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers =
            Collections.synchronizedMap(new HashMap<>());
    private final File resourcesLocation;

    public APILayer(int amountOfThreads, int port, @NotNull StorageLayer storageLayer,
                    @NotNull File resourcesLocation) throws IOException {
        server = new SimpleAPILayerServer(amountOfThreads, port, storageLayer, registeredUsers, revocationSecretsAcceptedPolicies,
                currentStorageElementIdentifiers, this);

        resourcesLocation.mkdirs();
        if (!resourcesLocation.canWrite()) throw new IllegalStateException("Can not write to the provided path.");
        this.resourcesLocation = resourcesLocation;
    }

    public void registerUser(@NotNull Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userIdentifiers,
                             @NotNull StorageElementIdentifier currentStorageElementIdentifier) {
        registeredUsers.put(userIdentifiers.getRight(), userIdentifiers.getLeft());
        currentStorageElementIdentifiers.put(userIdentifiers.getRight(), currentStorageElementIdentifier);
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

    private void deleteContentDirectory(@NotNull File directory) throws IOException {
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

    private @NotNull File obtainFileInstanceFor(@NotNull FileServerRequest fileServerRequest)
        throws IllegalArgumentException {
        var path = Path.of(resourcesLocation.getAbsolutePath(), fileServerRequest.getResourceLocation());
        return path.toFile();
    }

}
