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

/**
 * Class representing a Kademlia DHT-based realization of the {@link StorageLayer} interface.
 */
public class DHTStorageLayer implements StorageLayer {

    private final static Logger logger = Logger.getLogger(DHTStorageLayer.class.getName());

    private final JKademliaNode node;

    /**
     * Constructor for the {@link DHTStorageLayer} class.
     * @param   publicEntityIdentifier
     *          The {@link PublicEntityIdentifier} to identify this {@link JKademliaNode} with.
     * @param   port
     *          The port on which the local part of the DHT should run.
     * @throws  IOException
     *          If the boot process for the DHT failed.
     */
    public DHTStorageLayer(@NotNull PublicEntityIdentifier publicEntityIdentifier, int port) throws IOException {
        node = new JKademliaNode("",
                new KademliaId(publicEntityIdentifier.getNamespaceServiceProviderEmailAddressUserConcatenation().substring(0, 20)),
                port);
        logger.info(String.format("DHTStorageLayer (%s) initialized and running on port %s.", this, port));
    }

    /**
     * Constructor for the {@link DHTStorageLayer} class.
     * @param   publicEntityIdentifier
     *          The {@link PublicEntityIdentifier} to identify this {@link JKademliaNode} with.
     * @param   port
     *          The port on which the local part of the DHT should run.
     * @param   otherStorageLayers
     *          The other {@link DHTStorageLayer} instances to bootstrap with.
     * @throws  IOException
     *          If the boot process for the DHT failed.
     */
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
        var getParameter = new GetParameter(new KademliaId(adjustLengthStringForDHTIdentifiers(identifier.getIdentifier())),
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

    /**
     * Method to adjust the length of a provided String to 20 bytes.
     * @param   originalString
     *          The provided String, which may be shorter or longer than 20 bytes.
     * @return  A repeated version of the provided String, from which the first 20 bytes are taken as a substring.
     */
    private static String adjustLengthStringForDHTIdentifiers(@NotNull String originalString) {
        var copy = originalString.repeat((int) Math.ceil(20.0 / (double) originalString.length()));
        return copy.substring(0, 20);
    }

    /**
     * Class encapsulating the required functionality for the used Kademlia library.
     */
    static class DHTStorageElementContainer implements KadContent, Serializable {

        private final HashSet<StorageElement> storedElements;

        DHTStorageElementContainer(@NotNull HashSet<StorageElement> storedElements) {
            this.storedElements = storedElements;
        }

        @Override
        public KademliaId getKey() {
            if (storedElements.size() == 0) return null;
            else return new KademliaId(adjustLengthStringForDHTIdentifiers(
                    storedElements.iterator().next().getStorageLayerIdentifier().getIdentifier()));
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
