package vrielynckpieterjan.masterproef.storagelayer.dht;

import kademlia.JKademliaNode;
import kademlia.dht.GetParameter;
import kademlia.dht.KadContent;
import kademlia.exceptions.ContentNotFoundException;
import kademlia.node.KademliaId;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElement;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

import java.io.IOException;
import java.io.Serializable;
import java.util.HashSet;
import java.util.logging.Logger;

public class DHTStorageLayer implements StorageLayer {

    private final static Logger logger = Logger.getLogger(DHTStorageLayer.class.getName());

    private final JKademliaNode node;

    public DHTStorageLayer(@NotNull PublicEntityIdentifier publicEntityIdentifier, int port) throws IOException {
        node = new JKademliaNode("",
                new KademliaId(publicEntityIdentifier.getNamespaceServiceProviderEmailAddressUserConcatenation().substring(0, 20)),
                port);
        logger.info(String.format("DHTStorageLayer (%s) initialized and running on port %s.", this, port));
    }

    public DHTStorageLayer(@NotNull PublicEntityIdentifier publicEntityIdentifier, int port, DHTStorageLayer... otherStorageLayers)
            throws IOException {
        this(publicEntityIdentifier, port);
        for (var storageLayer : otherStorageLayers) {
            assert(storageLayer != null);
            node.bootstrap(storageLayer.node.getNode());
            logger.info(String.format("DHTStorageLayer (%s) bootstrapped using DHTStorageLayer (%s).", this, storageLayer));
        }
    }

    @Override
    public void put(@NotNull StorageElement newElement) throws IOException {
        var retrievedElements = retrieve(newElement.getStorageLayerIdentifier());
        retrievedElements.add(newElement);

        var elementContainer = new DHTStorageElementContainer(retrievedElements);
        node.put(elementContainer);
    }

    @Override
    public HashSet<StorageElement> retrieve(@NotNull StorageElementIdentifier identifier) throws IOException {
        var getParameter = new GetParameter(new KademliaId(identifier.getIdentifier().substring(0, 20)),
                DHTStorageElementContainer.class.getTypeName());
        try {
            var retrievedEntry = node.get(getParameter);
            var content = retrievedEntry.getContent();
            var elementContainer = SerializationUtils.deserialize(content);
            if (!(elementContainer instanceof DHTStorageElementContainer)) throw new ContentNotFoundException();
            return ((DHTStorageElementContainer) elementContainer).storedElements;
        } catch (Exception e) {
            return new HashSet<>();
        }
    }

    static class DHTStorageElementContainer implements KadContent, Serializable {

        private final HashSet<StorageElement> storedElements;

        DHTStorageElementContainer(@NotNull HashSet<StorageElement> storedElements) {
            this.storedElements = storedElements;
        }

        HashSet<StorageElement> getStoredElements() {
            return storedElements;
        }

        @Override
        public KademliaId getKey() {
            if (storedElements.size() == 0) return null;
            else return new KademliaId(storedElements.iterator().next().getStorageLayerIdentifier().getIdentifier().substring(0, 20));
        }

        @Override
        public String getType() {
            return DHTStorageElementContainer.class.getTypeName();
        }

        @Override
        public long getCreatedTimestamp() {
            return 0;
        }

        @Override
        public long getLastUpdatedTimestamp() {
            return 0;
        }

        @Override
        public String getOwnerId() {
            return "";
        }

        @Override
        public byte[] toSerializedForm() {
            return SerializationUtils.serialize(this);
        }

        @Override
        public KadContent fromSerializedForm(byte[] data) {
            return SerializationUtils.deserialize(data);
        }
    }
}
