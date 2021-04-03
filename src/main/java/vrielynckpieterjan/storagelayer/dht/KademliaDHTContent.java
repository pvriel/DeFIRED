package vrielynckpieterjan.storagelayer.dht;

import kademlia.dht.KadContent;
import kademlia.node.KademliaId;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.storagelayer.StorageElement;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;

/**
 * A container for the {@link vrielynckpieterjan.storagelayer.StorageElement} instances for the
 * {@link KademliaDHTStorageLayer} class.
 */
public class KademliaDHTContent implements KadContent, Serializable {

    private final HashSet<StorageElement> storageElements;

    /**
     * Constructor for the {@link KademliaDHTContent} class.
     * @param   storageElements
     *          The encapsulated {@link StorageElement}s.
     */
    KademliaDHTContent(@NotNull HashSet<StorageElement> storageElements) {
        this.storageElements = storageElements;
    }

    /**
     * Getter for the encapsulated {@link StorageElement}s.
     * @return  The {@link StorageElement}s.
     */
    HashSet<StorageElement> getStorageElements() {
        return storageElements;
    }

    @Override
    public KademliaId getKey() {
        if (storageElements.size() == 0) return null;
        Iterator<StorageElement> iterator = storageElements.iterator();
        StorageElement firstElement = iterator.next();
        String identifier = firstElement.getStorageLayerIdentifier().getIdentifier();
        identifier = identifier.substring(0, 20); // Kademlia DHT library limitation.
        return new KademliaId(identifier);
    }

    @Override
    public String getType() {
        return KademliaDHTContent.class.getTypeName();
    }

    @Override
    public long getCreatedTimestamp() {
        return 0; // Not used.
    }

    @Override
    public long getLastUpdatedTimestamp() {
        return 0; // Not used.
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
