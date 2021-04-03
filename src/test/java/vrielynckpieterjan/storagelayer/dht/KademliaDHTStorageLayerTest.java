package vrielynckpieterjan.storagelayer.dht;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class KademliaDHTStorageLayerTest {

    private final static Set<Integer> usedPorts = new HashSet<>();
    private KademliaDHTStorageLayer[] storageLayers = new KademliaDHTStorageLayer[2];

    private final StorageElementIdentifier[] storageElementIdentifiers = new StorageElementIdentifier[]{
            new StorageElementIdentifier("userOne"), new StorageElementIdentifier("userTwo")
    };
    private final Pair<PrivateEntityIdentifier, PublicEntityIdentifier> entityIdentifierPair = EntityIdentifier.generateEntityIdentifierPair();
    private final IssuerPartNamespaceAttestation issuerPartNamespaceAttestation = new IssuerPartNamespaceAttestation(
        entityIdentifierPair.getLeft(), entityIdentifierPair.getRight(), entityIdentifierPair.getRight(), "test",
            new RevocationCommitment(new RevocationSecret()), new RTreePolicy(PolicyRight.WRITE, "A"),
            new InetSocketAddress("localhost", 5678));

    private final NamespaceAttestation[] namespaceAttestations = new NamespaceAttestation[]{
            new NamespaceAttestation(storageElementIdentifiers[0], issuerPartNamespaceAttestation,
                    new RevocationCommitment(new RevocationSecret()), storageElementIdentifiers[0], entityIdentifierPair.getLeft()),
            new NamespaceAttestation(storageElementIdentifiers[1], issuerPartNamespaceAttestation,
                    new RevocationCommitment(new RevocationSecret()), storageElementIdentifiers[1], entityIdentifierPair.getLeft()),
    };

    @BeforeEach
    synchronized void setUp() throws IOException {
        int startPort = 12049;
        for (int i = 0; i < 2; i ++) {
            while (usedPorts.contains(startPort)) startPort += 1;
            storageLayers[i] = new KademliaDHTStorageLayer(startPort, namespaceAttestations[i]);
            usedPorts.add(startPort);
        }

        storageLayers[1].bootstrap(storageLayers[0].getNode());
    }

    @Test
    void putAndRetrieve() throws IOException, InterruptedException {
        // Put.
        StorageElementIdentifier identifier = new StorageElementIdentifier("ABCDEFGHIJKLMNIOPQRS");
        String data = "This is a test.";
        StorageElementRealization storageElement = new StorageElementRealization(identifier.getIdentifier(), data);
        storageLayers[1].put(storageElement);
        Thread.sleep(1000);

        // Retrieve.
        for (KademliaDHTStorageLayer storageLayer : storageLayers) {
            Set<StorageElement> retrievedElements = storageLayer.retrieve(identifier);
            assertEquals(1, retrievedElements.size());

            Iterator<StorageElement> iterator = retrievedElements.iterator();
            StorageElement retrievedStorageElement = iterator.next();
            assertTrue(retrievedStorageElement instanceof StorageElementRealization);
            assertEquals(identifier.getIdentifier(), retrievedStorageElement.getStorageLayerIdentifier().getIdentifier());
            assertEquals(data, ((StorageElementRealization) retrievedStorageElement).data);
        }
    }

    public static class StorageElementRealization extends StorageElement {

        final String data;

        public StorageElementRealization(@NotNull String identifier, @NotNull String data) {
            super(new StorageElementIdentifier(identifier));
            this.data = data;
        }

        @Override
        public String toString() {
            return "StorageElementRealization{" +
                    "data='" + data + '\'' +
                    '}';
        }
    }
}