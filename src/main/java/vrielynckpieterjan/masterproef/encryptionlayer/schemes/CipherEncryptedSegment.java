package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Abstract class representing a {@link DecryptableSegment}, which is
 * encrypted / decrypted by using {@link Cipher} instances.
 * @param   <DecryptedObjectType>
 *          The type of the decrypted version of the object.
 * @param   <EncryptionKey>
 *          The type of the key used to encrypt the original object.
 * @param   <DecryptionKey>
 *          The type of the key used to decrypt the encrypted segment.
 */
abstract class CipherEncryptedSegment<DecryptedObjectType extends Serializable, EncryptionKey, DecryptionKey>
        implements DecryptableSegment<DecryptedObjectType, DecryptionKey> {

    private final static Logger logger = Logger.getLogger(CipherEncryptedSegment.class.getName());

    private final byte[] encryptedSegment;

    /**
     * Constructor for the {@link CipherEncryptedSegment} class.
     * @param   originalObject
     *          The original object to encrypt.
     * @param   encryptionKey
     *          The key to encrypt the original object with.
     * @throws  IllegalArgumentException
     *          If an illegal key was provided.
     */
    public CipherEncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull EncryptionKey encryptionKey) throws IllegalArgumentException {
        byte[] serializedOriginalObject = SerializationUtils.serialize(originalObject);
        encryptedSegment = encrypt(serializedOriginalObject, encryptionKey);
    }

    /**
     * Constructor for the {@link CipherEncryptedSegment} class.
     * @param   encryptedSegment
     *          The (already) encrypted segment as a byte array.
     */
    protected CipherEncryptedSegment(byte[] encryptedSegment) {
        this.encryptedSegment = encryptedSegment;
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

    @Override
    public @NotNull DecryptedObjectType decrypt(@NotNull DecryptionKey decryptionKey) throws IllegalArgumentException {
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

    /**
     * Method to call a {@link Cipher} procedure to encrypt / decrypt the provided byte array with the given arguments.
     * @param   instanceName
     *          The name of the encryption method which is used to initialized the {@link Cipher} instance with.
     * @param   cipherMode
     *          The {@link Cipher} mode.
     * @param   element
     *          The element to encrypt.
     * @param   key
     *          The key to encrypt the element argument with.
     * @return  The encrypted element as a byte array.
     * @throws  IllegalArgumentException
     *          If the provided key could not be used to encrypt the provided byte array with.
     * @apiNote The System.exit() method is called if no {@link Cipher} instance can be initialized for the provided
     *          instanceName argument.
     */
    protected byte[] applyCipherMode(@NotNull String instanceName, int cipherMode, byte[] element, @NotNull Key key)
            throws IllegalArgumentException {
        try {
            Cipher cipher = Cipher.getInstance(instanceName);
            cipher.init(cipherMode, key);
            return cipher.doFinal(element);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.severe(String.format("An %s Cipher instance could not be initialized (reason: %s). Due to" +
                    " the severity of this problem, the program will now exit.", instanceName, e));
            e.printStackTrace();
            System.exit(1);
            return null;
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CipherEncryptedSegment<?, ?, ?> that = (CipherEncryptedSegment<?, ?, ?>) o;
        return Arrays.equals(encryptedSegment, that.encryptedSegment);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encryptedSegment);
    }

    @Override
    public byte[] serialize() throws IOException {
        return encryptedSegment;
    }

}
