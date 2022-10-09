package kademlia.message;

import kademlia.node.KademliaId;
import kademlia.node.Node;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * A message sent to other nodes requesting the K-Closest nodes to a key sent in this message.
 *
 * @author Joshua Kissoon
 * @created 20140218
 */
public class NodeLookupMessage implements Message {

    public static final byte CODE = 0x05;
    private Node origin;
    private KademliaId lookupId;

    /**
     * A new NodeLookupMessage to find nodes
     *
     * @param origin The Node from which the message is coming from
     * @param lookup The key for which to lookup nodes for
     */
    public NodeLookupMessage(Node origin, KademliaId lookup) {
        this.origin = origin;
        this.lookupId = lookup;
    }

    public NodeLookupMessage(DataInputStream in) throws IOException {
        this.fromStream(in);
    }

    @Override
    public final void fromStream(DataInputStream in) throws IOException {
        this.origin = new Node(in);
        this.lookupId = new KademliaId(in);
    }

    @Override
    public void toStream(DataOutputStream out) throws IOException {
        this.origin.toStream(out);
        this.lookupId.toStream(out);
    }

    public Node getOrigin() {
        return this.origin;
    }

    public KademliaId getLookupId() {
        return this.lookupId;
    }

    @Override
    public byte code() {
        return CODE;
    }

    @Override
    public String toString() {
        return "NodeLookupMessage[origin=" + origin + ",lookup=" + lookupId + "]";
    }
}
