package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Class representing an EC {@link CipherEncryptedSegment}.
 * @param   <DecryptedObjectType>
 *          The object type of the decrypted segment.
 * @implNote
 *          This class uses AES encryption to encrypt the original object with
 *          and uses EC encryption to encrypt the used, randomly 32-byte long generated AES key.
 *          This is due to the fact that the RSA encryption scheme, which was originally used instead of the EC encryption scheme,
 *          can't be used to encrypt objects of any length.
 */
public class ECCipherEncryptedSegment<DecryptedObjectType extends Serializable>
        extends CipherEncryptedSegment<DecryptedObjectType, PublicKey, PrivateKey> {

    private final static Logger logger = Logger.getLogger(ECCipherEncryptedSegment.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private AESCipherEncryptedSegment<byte[]> encapsulatedAESEncryptedSegment;

    /**
     * Constructor for the {@link ECCipherEncryptedSegment} class.
     * @param   encryptedSegment
     *          The encrypted segment for the {@link CipherEncryptedSegment} superclass.
     * @param   encapsulatedAESEncryptedSegment
     *          The encapsulated AES encrypted segment.
     */
    protected ECCipherEncryptedSegment(byte[] encryptedSegment, @NotNull AESCipherEncryptedSegment<byte[]> encapsulatedAESEncryptedSegment) {
        super(encryptedSegment);
        this.encapsulatedAESEncryptedSegment = encapsulatedAESEncryptedSegment;
    }

    /**
     * Constructor for the {@link ECCipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param publicKey     The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public ECCipherEncryptedSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        super(originalObject, publicKey);
    }

    /**
     * Constructor for the {@link ECCipherEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param privateEntityIdentifier     The {@link PrivateEntityIdentifier} to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public ECCipherEncryptedSegment(@NotNull DecryptedObjectType originalObject,
                                    @NotNull PrivateEntityIdentifier privateEntityIdentifier) throws IllegalArgumentException {
        super(originalObject, privateEntityIdentifier.getRSAIdentifier());
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull PublicKey publicKey) throws IllegalArgumentException {
        // Generate random String for the AES encryption.
        String AESKey = RandomStringUtils.randomAlphanumeric(32);

        // Encrypt original object using AES encryption.
        encapsulatedAESEncryptedSegment = new AESCipherEncryptedSegment<>(serializedOriginalObject, AESKey);

        // Encrypt AES key using EC encryption.
        return applyECCipherMode(Cipher.ENCRYPT_MODE, AESKey.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    @Override
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull PrivateKey privateKey) throws IllegalArgumentException {
        // Decrypt the encrypted version of the AES key using the EC key.
        byte[] decryptedAESKey = applyECCipherMode(Cipher.DECRYPT_MODE, encryptedSegment, privateKey);

        // Decrypt the AES encrypted segment.
        String originalAESKey = new String(decryptedAESKey, StandardCharsets.UTF_8);
        return encapsulatedAESEncryptedSegment.decrypt(originalAESKey);
    }

    /**
     * Method to decrypt the {@link ECCipherEncryptedSegment}.
     * @param   publicEntityIdentifier
     *          The {@link PublicEntityIdentifier} to decrypt the {@link ECCipherEncryptedSegment} with.
     * @return  The decrypted and deserialized {@link ECCipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key can't be used to decrypt the {@link ECCipherEncryptedSegment}.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PublicEntityIdentifier publicEntityIdentifier)
        throws IllegalArgumentException {
        return this.decrypt(publicEntityIdentifier.getRSAIdentifier());
    }

    /**
     * Method to encrypt / decrypt a byte array using a provided key, using the EC encryption scheme.
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
    private byte[] applyECCipherMode(int cipherMode, byte[] element, @NotNull Key key) throws IllegalArgumentException {
        return applyCipherMode("ECIESwithAES-CBC", cipherMode, element, key);
    }

    /**
     * A static method to generate an EC {@link KeyPair}.
     * @return  The {@link KeyPair}.
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
            keyPairGenerator.initialize(spec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            logger.severe(String.format("An RSA KeyPair instance could not be initialized (reason: %s). Due to " +
                    "the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    /**
     * Method to check if the provided {@link PrivateKey} and {@link PublicKey} instances are actually
     * part of the same RSA {@link KeyPair}.
     * @param   privateKey
     *          A possible RSA {@link PrivateKey}.
     * @param   publicKey
     *          A possible RSA {@link PrivateKey}.
     * @return  True if the two provided {@link Key}s were originally part of an RSA {@link KeyPair}; false otherwise.
     */
    public static boolean keysPartOfKeypair(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) {
        try {
            String randomString = RandomStringUtils.randomAlphanumeric(32);
            ECCipherEncryptedSegment<String> encryptedRandomString = new ECCipherEncryptedSegment<>(randomString, publicKey);
            String decrypted = encryptedRandomString.decrypt(privateKey);
            return randomString.equals(decrypted);
        } catch (IllegalArgumentException ignored) {
            return false; // Invalid EC PrivateKey or PublicKey.
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ECCipherEncryptedSegment<?> that = (ECCipherEncryptedSegment<?>) o;
        return encapsulatedAESEncryptedSegment.equals(that.encapsulatedAESEncryptedSegment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), encapsulatedAESEncryptedSegment);
    }

    @Override
    public String toString() {
        return "ECCipherEncryptedSegment{" +
                "encapsulatedAESEncryptedSegment=" + encapsulatedAESEncryptedSegment +
                '}';
    }

    @Override
    public byte[] serialize() throws IOException {
        byte[] encryptedSegment = super.serialize();
        byte[] encapsulatedAESEncryptedSegment = ExportableUtils.serialize(this.encapsulatedAESEncryptedSegment);

        ByteBuffer byteBuffer = ByteBuffer.allocate(encryptedSegment.length + encapsulatedAESEncryptedSegment.length + 4);
        byteBuffer.putInt(encryptedSegment.length);
        byteBuffer.put(encryptedSegment);
        byteBuffer.put(encapsulatedAESEncryptedSegment);

        return byteBuffer.array();
    }

    @NotNull
    public static ECCipherEncryptedSegment deserialize(@NotNull ByteBuffer byteBuffer) throws IOException {
        byte[] encryptedSegment = new byte[byteBuffer.getInt()];
        byteBuffer.get(encryptedSegment);

        byte[] encapsulatedAESEncryptedSegmentAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(encapsulatedAESEncryptedSegmentAsByteArray);
        AESCipherEncryptedSegment<byte[]> encapsulatedAESEncryptedSegment =
                ExportableUtils.deserialize(encapsulatedAESEncryptedSegmentAsByteArray, AESCipherEncryptedSegment.class);

        return new ECCipherEncryptedSegment(encryptedSegment, encapsulatedAESEncryptedSegment);
    }
}
