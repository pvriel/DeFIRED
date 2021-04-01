package vrielynckpieterjan.encryptionlayer;

import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.logging.Logger;

/**
 * Class representing an RSA {@link EncryptedSegment}.
 * @param   <DecryptedObjectType>
 *          The object type of the decrypted segment.
 * @implNote
 *          This class uses AES encryption to encrypt the original object
 *          and uses RSA encryption to encrypt the used, randomly 32-byte long generated AES key.
 *          This is due to the fact that the RSA encryption scheme can't be used
 *          to encrypt objects of any length.
 */
public class RSAEncryptedSegment<DecryptedObjectType extends Serializable>
        extends EncryptedSegment<DecryptedObjectType, PublicKey, PrivateKey> {

    private final static Logger logger = Logger.getLogger(RSAEncryptedSegment.class.getName());

    private AESEncryptedSegment<byte[]> encapsulatedAESEncryptedSegment;

    /**
     * Constructor for the {@link RSAEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param publicKey     The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public RSAEncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        super(originalObject, publicKey);
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        // Generate random String for the AES encryption.
        String AESKey = RandomStringUtils.randomAlphanumeric(32);
        // Encrypt original object using AES encryption.
        encapsulatedAESEncryptedSegment = new AESEncryptedSegment<>(serializedOriginalObject, AESKey);
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
}
