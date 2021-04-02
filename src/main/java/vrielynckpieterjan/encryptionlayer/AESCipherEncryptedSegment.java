package vrielynckpieterjan.encryptionlayer;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * Class representing an AES {@link CipherEncryptedSegment}.
 * @param   <DecryptedObjectType>
 *          The type of the decrypted object.
 */
public class AESCipherEncryptedSegment<DecryptedObjectType extends Serializable> extends CipherEncryptedSegment<DecryptedObjectType, String, String> {

    private final static Logger logger = Logger.getLogger(AESCipherEncryptedSegment.class.getName());

    /**
     * Constructor for the {@link AESCipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param encryptionKey              The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public AESCipherEncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull String encryptionKey) throws IllegalArgumentException {
        super(originalObject, encryptionKey);
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull String encryptionKey) throws IllegalArgumentException {
        return applyCipherMode(Cipher.ENCRYPT_MODE, serializedOriginalObject, encryptionKey);
    }

    @Override
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull String decryptionKey) throws IllegalArgumentException {
        return applyCipherMode(Cipher.DECRYPT_MODE, encryptedSegment, decryptionKey);
    }

    /**
     * Method to encrypt / decrypt a byte array using a provided key.
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
    private byte[] applyCipherMode(int cipherMode, byte[] element, @NotNull String key) throws IllegalArgumentException {
        key = adjustKeyLength(key); // If I ever change this line of code: cf. statement further.
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, secretKeySpec);
            return cipher.doFinal(element);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            /*
            Normally, a distinction should be made for the Exceptions which can be thrown by the getInstance statement
            and the init statement, as the user can also provide an invalid key (== a key with an invalid length, or null).
            However, due to the @NotNull annotation and the adjustKeyLength method invocation, both situations can
            be reduced to one, which allows us to use one catch statement here instead of two.
             */
            logger.severe(String.format("An AES Cipher instance could not be initialized (reason: %s). Due to" +
                    " the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
            return null;
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Method to adjust provided Strings that are either too long or too short by using repetition or taking substrings
     * in order to use them as keys for the AES-256 algorithm.
     * @param   originalKey
     *          The original String.
     * @return  The original String which has been repeated to obtain exactly / more than 32 bytes, after which
     *          the first 32 bytes are taken.
     */
    private String adjustKeyLength(@NotNull String originalKey) {
        if (originalKey.length() == 32) return originalKey;
        else if (originalKey.length() > 32) {
            logger.info(String.format("[%s] A key of %s bytes has been provided for the AES-256 algorithm." +
                    " Only the first 32 bytes will be used instead.", this, originalKey.length()));
            return originalKey.substring(0, 32);
        } else {
            logger.info(String.format("[%s] A key of %s byte(s) has been provided for the AES-256 algorithm." +
                    " The original key will be repeated to obtain a key of 32 bytes instead.", this, originalKey.length()));

            int amountOfRepetitionRequired = (int) Math.ceil(32.0/(double) originalKey.length());
            originalKey = originalKey.repeat(amountOfRepetitionRequired);
            return originalKey.substring(0, 32);
        }
    }
}
