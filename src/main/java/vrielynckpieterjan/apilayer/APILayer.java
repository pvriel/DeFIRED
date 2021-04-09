package vrielynckpieterjan.apilayer;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.apilayer.server.SimpleAPILayerServer;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;

public class APILayer extends Thread implements Closeable {

    private final SimpleAPILayerServer server;
    private final Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies
            = Collections.synchronizedMap(new HashMap<>());
    private final Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers =
            Collections.synchronizedMap(new HashMap<>());

    public APILayer(int amountOfThreads, int port, @NotNull StorageLayer storageLayer) throws IOException {
        server = new SimpleAPILayerServer(amountOfThreads, port, storageLayer, registeredUsers, revocationSecretsAcceptedPolicies,
                currentStorageElementIdentifiers);
    }

    public void registerUser(@NotNull Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userIdentifiers,
                             @NotNull StorageElementIdentifier currentStorageElementIdentifier) {
        registeredUsers.put(userIdentifiers.getRight(), userIdentifiers.getLeft());
    }

    @Override
    public void run() {
        server.start();
    }

    @Override
    public void close() {
        server.interrupt();
    }
}
