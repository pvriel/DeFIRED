package vrielynckpieterjan.encryptionlayer;

import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Abstract class representing an ecrypted segment.
 * @param   <DecryptedObjectType>
 *          The type of the decrypted version of the object.
 * @param   <EncryptionKey>
 *          The type of the key used to encrypt the original object.
 * @param   <DecryptionKey>
 *          The type of the key used to decrypt the encrypted segment.
 */
abstract class EncryptedSegment<DecryptedObjectType extends Serializable, EncryptionKey, DecryptionKey> implements Serializable {

    private final byte[] encryptedSegment;

    /**
     * Constructor for the {@link EncryptedSegment} class.
     * @param   originalObject
     *          The original object to encrypt.
     * @param   encryptionKey
     *          The key to encrypt the original object with.
     * @throws  IllegalArgumentException
     *          If an illegal key was provided.
     */
    public EncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull EncryptionKey encryptionKey) throws IllegalArgumentException {
        byte[] serializedOriginalObject = SerializationUtils.serialize(originalObject);
        encryptedSegment = encrypt(serializedOriginalObject, encryptionKey);
    }

    /**
     * Method to encrypt the given data, using the provided encryption key;
     * @param   serializedOriginalObject
     *          The byte array to encrypt.
     * @param   encryptionKey
     *          The encryption key to encrypt the byte array with.
     * @return  The encrypted data.
     * @throws  IllegalArgumentException
     *          If an illegal key was provided.
     */
    protected abstract byte[] encrypt(byte[] serializedOriginalObject, @NotNull EncryptionKey encryptionKey) throws IllegalArgumentException;

    /**
     * Method to decrypt the {@link EncryptedSegment}.
     * @param   decryptionKey
     *          The key to decrypt the {@link EncryptedSegment} with.
     * @return  The decrypted and deserialized {@link EncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key can't be used to decrypt the {@link EncryptedSegment}.
     */
    public DecryptedObjectType decrypt(@NotNull DecryptionKey decryptionKey) throws IllegalArgumentException {
        byte[] decryptedSegmentByteArray = decrypt(encryptedSegment, decryptionKey);
        return SerializationUtils.deserialize(decryptedSegmentByteArray);
    }

    /**
     * Method to decrypt the provided byte array.
     * @param   encryptedSegment
     *          The byte array containing the encrypted segment.
     * @param   decryptionKey
     *          The key provided to decrypt the encrypted byte array.
     * @return  The decrypted content as a byte array.
     * @throws  IllegalArgumentException
     *          If the byte array can't be decrypted using the provided key.
     */
    protected abstract byte[] decrypt(byte[] encryptedSegment, @NotNull DecryptionKey decryptionKey) throws IllegalArgumentException;

}
