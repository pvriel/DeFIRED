package vrielynckpieterjan.encryptionlayer.schemes;

import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Class representing an RSA {@link CipherEncryptedSegment}.
 * @param   <DecryptedObjectType>
 *          The object type of the decrypted segment.
 * @implNote
 *          This class uses AES encryption to encrypt the original object
 *          and uses RSA encryption to encrypt the used, randomly 32-byte long generated AES key.
 *          This is due to the fact that the RSA encryption scheme can't be used
 *          to encrypt objects of any length.
 */
public class RSACipherEncryptedSegment<DecryptedObjectType extends Serializable>
        extends CipherEncryptedSegment<DecryptedObjectType, PublicKey, PrivateKey> {

    private final static Logger logger = Logger.getLogger(RSACipherEncryptedSegment.class.getName());

    private AESCipherEncryptedSegment<byte[]> encapsulatedAESEncryptedSegment;

    /**
     * Constructor for the {@link RSACipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param publicKey     The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public RSACipherEncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        super(originalObject, publicKey);
    }

    /**
     * Constructor for the {@link RSACipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param publicEntityIdentifier     The {@link PublicEntityIdentifier} to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public RSACipherEncryptedSegment(@NotNull DecryptedObjectType originalObject,
                                     @NotNull PublicEntityIdentifier publicEntityIdentifier) throws IllegalArgumentException {
        super(originalObject, publicEntityIdentifier.getRSAEncryptionIdentifier());
    }

    /**
     * Constructor for the {@link RSACipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param privateEntityIdentifier     The {@link PrivateEntityIdentifier} to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public RSACipherEncryptedSegment(@NotNull DecryptedObjectType originalObject,
                                     @NotNull PrivateEntityIdentifier privateEntityIdentifier) throws IllegalArgumentException {
        super(originalObject, privateEntityIdentifier.getRSADecryptionIdentifier());
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        // Generate random String for the AES encryption.
        String AESKey = RandomStringUtils.randomAlphanumeric(32);
        // Encrypt original object using AES encryption.
        encapsulatedAESEncryptedSegment = new AESCipherEncryptedSegment<>(serializedOriginalObject, AESKey);
        // Encrypt AES key using RSA encryption.
        return applyRSACipherMode(Cipher.ENCRYPT_MODE, AESKey.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    @Override
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull PrivateKey privateKey) throws IllegalArgumentException {
        byte[] decryptedAESKey = applyRSACipherMode(Cipher.DECRYPT_MODE, encryptedSegment, privateKey);
        String originalAESKey = new String(decryptedAESKey, StandardCharsets.UTF_8);
        return encapsulatedAESEncryptedSegment.decrypt(originalAESKey);
    }

    /**
     * Method to decrypt the {@link RSACipherEncryptedSegment}.
     * @param   privateEntityIdentifier
     *          The {@link PrivateEntityIdentifier} to decrypt the {@link RSACipherEncryptedSegment} with.
     * @return  The decrypted and deserialized {@link RSACipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key can't be used to decrypt the {@link RSACipherEncryptedSegment}.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier)
            throws IllegalArgumentException {
        return this.decrypt(privateEntityIdentifier.getRSAEncryptionIdentifier());
    }

    /**
     * Method to decrypt the {@link RSACipherEncryptedSegment}.
     * @param   publicEntityIdentifier
     *          The {@link PublicEntityIdentifier} to decrypt the {@link RSACipherEncryptedSegment} with.
     * @return  The decrypted and deserialized {@link RSACipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key can't be used to decrypt the {@link RSACipherEncryptedSegment}.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PublicEntityIdentifier publicEntityIdentifier)
        throws IllegalArgumentException {
        return this.decrypt(publicEntityIdentifier.getRSADecryptionIdentifier());
    }

    /**
     * Method to encrypt / decrypt a byte array using a provided key, using the RSA encryption scheme.
     * @param   cipherMode
     *          The {@link Cipher} mode.
     * @param   element
     *          The element to encrypt / decrypt as a byte array.
     * @param   key
     *          The key to encrypt / decrypt the byte array with.
     * @return  The encrypted / decrypted version of the byte array.
     * @throws  IllegalArgumentException
     *          If the content of the byte array can't be encrypted / decrypted using the provided key, or
     *          if an invalid cipherMode argument is provided.
     */
    private byte[] applyRSACipherMode(int cipherMode, byte[] element, @NotNull Key key) throws IllegalArgumentException {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(cipherMode, key);
            return cipher.doFinal(element);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            logger.severe(String.format("An RSA Cipher instance could not be initialized (reason: %s). Due to" +
                    " the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
            return null;
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * A static method to generate an RSA {@link KeyPair}.
     * @return  The {@link KeyPair}.
     */
    public static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("RSA").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            logger.severe(String.format("An RSA KeyPair instance could not be initialized (reason: %s). Due to " +
                    "the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    /**
     * Method to check if the provided {@link PrivateKey} and {@link PublicKey} instances are actually
     * part of an RSA {@link KeyPair}.
     * @param   privateKey
     *          A possible RSA {@link PrivateKey}.
     * @param   publicKey
     *          A possible RSA {@link PrivateKey}.
     * @return  True if the two provided {@link Key}s were originally part of an RSA {@link KeyPair}; false otherwise.
     */
    public static boolean keysPartOfKeypair(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) {
        try {
            String randomString = RandomStringUtils.randomAlphanumeric(32);
            RSACipherEncryptedSegment<String> encryptedRandomString = new RSACipherEncryptedSegment<>(randomString, publicKey);
            String decrypted = encryptedRandomString.decrypt(privateKey);
            return randomString.equals(decrypted);
        } catch (IllegalArgumentException ignored) {
            return false; // Invalid RSA PrivateKey or PublicKey.
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RSACipherEncryptedSegment<?> that = (RSACipherEncryptedSegment<?>) o;
        return encapsulatedAESEncryptedSegment.equals(that.encapsulatedAESEncryptedSegment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), encapsulatedAESEncryptedSegment);
    }
}
