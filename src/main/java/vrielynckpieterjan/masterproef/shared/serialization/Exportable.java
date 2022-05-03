package vrielynckpieterjan.masterproef.shared.serialization;

import java.io.IOException;
import java.io.Serializable;

/**
 * Interface for custom serialization.
 * This interface extends the {@link java.io.Serializable} interface for legacy reasons.
 */
public interface Exportable extends Serializable {

    /**
     * Method to serialize the {@link Exportable} instance.
     * @return  The {@link Exportable} instance as a byte array.
     */
    byte[] serialize() throws IOException;
}
