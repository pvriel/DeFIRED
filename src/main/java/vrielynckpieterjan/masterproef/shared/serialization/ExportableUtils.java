package vrielynckpieterjan.masterproef.shared.serialization;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

/**
 * Abstract class to handle {@link Exportable} instances.
 */
public abstract class ExportableUtils {

    /**
     * Static method to serialize {@link Exportable} instances.
     * @param   exportable
     *          The {@link Exportable} instance.
     * @return  The {@link Exportable} instance as a byte array.
     */
    public static byte[] serialize(@NotNull Exportable exportable) throws IOException {
        return exportable.serialize();
    }

    /**
     * Static method to deserialize a serialized {@link Exportable} instance.
     * @param   bytes
     *          The byte array.
     * @param   clazz
     *          The original class of the serialized {@link Exportable} instance.
     * @return  The deserialized {@link Exportable} instance.
     * @param   <T>
     *          The original type of the serialized {@link Exportable} instance.
     * @throws  IOException
     *          If the given byte array could not be deserialized to the given {@link Exportable} realization.
     */
    @NotNull
    public static <T extends Exportable> T deserialize(byte[] bytes, @NotNull Class<T> clazz) throws IOException {
        try {
            Method deserializationMethod = clazz.getMethod("deserialize", ByteBuffer.class);
            Object result = deserializationMethod.invoke(null, ByteBuffer.wrap(bytes));
            return (T) result;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
