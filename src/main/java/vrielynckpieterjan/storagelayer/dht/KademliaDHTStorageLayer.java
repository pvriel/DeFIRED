package vrielynckpieterjan.storagelayer.dht;

import com.google.common.hash.Hashing;
import kademlia.JKademliaNode;
import kademlia.dht.GetParameter;
import kademlia.dht.JKademliaStorageEntry;
import kademlia.node.KademliaId;
import kademlia.node.Node;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.NamespaceAttestation;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.IOException;
import java.util.HashSet;
import java.util.logging.Logger;

/**
 * Class implementing the {@link vrielynckpieterjan.storagelayer.StorageLayer} interface, to simulate the behaviour
 * of the storage layer of the decentralized access policy framework using a Kademlia DHT.
 * TODO: fix the way in which the kademlia library is imported in this project; add it as a Gradle dependency instead.
 */
public class KademliaDHTStorageLayer implements StorageLayer<Node> {

    private final static Logger logger = Logger.getLogger(KademliaDHTStorageLayer.class.getName());

    private final JKademliaNode kademliaNode;

    public KademliaDHTStorageLayer(int port, @NotNull NamespaceAttestation namespaceAttestation) throws IOException {
        // Generate the node ID first.
        byte[] serializedNamespaceAttestation = SerializationUtils.serialize(namespaceAttestation);
        String nodeID = Hashing.sha512().hashBytes(serializedNamespaceAttestation).toString();
        nodeID = nodeID.substring(0, 20); // Kademlia library limitation.

        kademliaNode = new JKademliaNode("", new KademliaId(nodeID), port);
        logger.info(String.format("[%s] Initialized using Kademlia ID (%s) on port %s.", this, nodeID, port));
    }

    /**
     * Getter for the Kademlia DHT {@link Node}.
     * @return  The {@link Node} of this {@link StorageLayer}.
     */
    public Node getNode() {
        return kademliaNode.getNode();
    }

    @Override
    public void bootstrap(@NotNull Node node) throws IOException {
        kademliaNode.bootstrap(node);
        logger.info(String.format("[%s] Bootstrap with Node (%s) completed.", this, node));
    }

    @Override
    public synchronized void put(@NotNull StorageElement newElement) throws IOException {
        HashSet<StorageElement> oldElements = retrieve(newElement.getStorageLayerIdentifier());
        oldElements.add(newElement);

        KademliaDHTContent encapsulatedContent = new KademliaDHTContent(oldElements);
        kademliaNode.put(encapsulatedContent);
        logger.info(String.format("[%s] %s element(s) stored with identifier (%s).", this,
                oldElements.size(), newElement.getStorageLayerIdentifier()));
    }

    @Override
    public HashSet<StorageElement> retrieve(@NotNull String identifier) {
        identifier = identifier.substring(0, 20); // Kademlia DHT library limitation.
        GetParameter getParameter = new GetParameter(new KademliaId(identifier), KademliaDHTContent.class.getTypeName(), "");
        try {
            JKademliaStorageEntry storageEntry = kademliaNode.get(getParameter);
            KademliaDHTContent kademliaDHTContent = SerializationUtils.deserialize(storageEntry.getContent());
            return kademliaDHTContent.getStorageElements();
        } catch (Exception e) {
            logger.warning(String.format("An Exception occurred while trying to retrieve stored element(s) from the " +
                    "DHT with identifier (%s) (reason: %s); an empty HashSet will be returned.", identifier, e));
            return new HashSet<>();
        }
    }
}
