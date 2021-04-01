package vrielynckpieterjan.storagelayer.dht;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.applicationlayer.NamespaceAttestation;
import vrielynckpieterjan.storagelayer.StorageElement;

import java.io.IOException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class KademliaDHTStorageLayerTest {

    private final static Set<Integer> usedPorts = new HashSet<>();
    private KademliaDHTStorageLayer[] storageLayers = new KademliaDHTStorageLayer[2];
    private final NamespaceAttestation[] namespaceAttestations = new NamespaceAttestation[]{
            new NamespaceAttestation("userOne"),
            new NamespaceAttestation("userTwo")
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
        String identifier = "ABCDEFGHIJKLMNIOPQRS";
        String data = "This is a test.";
        StorageElementRealization storageElement = new StorageElementRealization(identifier, data);
        storageLayers[1].put(storageElement);
        Thread.sleep(1000);

        // Retrieve.
        for (KademliaDHTStorageLayer storageLayer : storageLayers) {
            Set<StorageElement> retrievedElements = storageLayer.retrieve(identifier);
            assertEquals(1, retrievedElements.size());

            Iterator<StorageElement> iterator = retrievedElements.iterator();
            StorageElement retrievedStorageElement = iterator.next();
            assertTrue(retrievedStorageElement instanceof StorageElementRealization);
            assertEquals(identifier, retrievedStorageElement.getStorageLayerIdentifier());
            assertEquals(data, ((StorageElementRealization) retrievedStorageElement).data);
        }
    }

    public static class StorageElementRealization extends StorageElement {

        final String data;

        public StorageElementRealization(@NotNull String identifier, @NotNull String data) {
            super(identifier);
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