package kademlia.util.serializer;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * A Serializer is used to transform data to and from a specified form.
 * <p>
 * Here we define the structure of any Serializer used in Kademlia
 *
 * @param <T> The type of content being serialized
 * @author Joshua Kissoon
 * @since 20140225
 */
public interface KadSerializer<T> {

    /**
     * Write a KadContent to a DataOutput stream
     *
     * @param data The data to write
     * @param out  The output Stream to write to
     * @throws IOException
     */
    public void write(T data, DataOutputStream out) throws IOException;

    /**
     * Read data of type T from a DataInput Stream
     *
     * @param in The InputStream to read the data from
     * @return T Data of type T
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public T read(DataInputStream in) throws IOException, ClassNotFoundException;
}
