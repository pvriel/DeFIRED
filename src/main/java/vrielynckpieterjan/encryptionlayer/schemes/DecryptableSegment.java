package vrielynckpieterjan.encryptionlayer.schemes;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Interface representing a segment which can be decrypted.
 * @param   <DecryptedObjectType>
 *          The type of the object returned after the decryption process.
 * @param   <DecryptionKey>
 *          The type of the key required to perform the decryption process.
 */
public interface DecryptableSegment<DecryptedObjectType extends Serializable, DecryptionKey> extends Serializable {

    /**
     * Method to decrypt the {@link DecryptableSegment}.
     * @param   decryptionKey
     *          The key to decrypt the {@link DecryptableSegment} with.
     * @return  The decrypted and deserialized {@link DecryptableSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key can't be used to decrypt the {@link DecryptableSegment}.
     */
    @NotNull DecryptedObjectType decrypt(@NotNull DecryptionKey decryptionKey) throws IllegalArgumentException;
}
