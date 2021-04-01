package vrielynckpieterjan.encryptionlayer;

import cryptid.CryptID;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.SecurityLevel;
import cryptid.ibe.exception.SetupException;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;

import java.util.Optional;
import java.util.logging.Logger;

/**
 * Class representing an IBE {@link EncryptedSegment}.
 * @implNote    Unlike the other {@link EncryptedSegment} implementations,
 *              this class can only be used to encrypt Strings due to the limitations
 *              of the used IBE encryption library.
 */
public class IBEEncryptedSegment
        extends EncryptedSegment<String, String, cryptid.ibe.domain.PrivateKey> {

    private final static Logger logger = Logger.getLogger(IBEEncryptedSegment.class.getName());
    private static IdentityBasedEncryption ibe;

    static {
        try {
            ibe = CryptID.setupBonehFranklin(SecurityLevel.LOWEST);
            logger.info(String.format("IdentityBasedEncryption (%s) initialized.", ibe));
        } catch (SetupException e) {
            logger.severe(String.format("The Boneh Franklin IdentityBasedEncryption instance could not be " +
                    "initialized (reason: %s). Due to the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Constructor for the {@link IBEEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param s              The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public IBEEncryptedSegment(@NotNull String originalObject, @NotNull String s) throws IllegalArgumentException {
        super(originalObject, s);
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull String s) throws IllegalArgumentException {
        // TODO: little bit unfortunately that I have to deserialize a serialized String...
        //  Instead, optimize the code (maybe use an interface at the top of this EncryptedSegment
        //  hierarchy, which only requires a decrypt method?)
        String originalObject = SerializationUtils.deserialize(serializedOriginalObject);
        CipherTextTuple cipherTextTuple = ibe.encrypt(originalObject, s);
        return SerializationUtils.serialize(cipherTextTuple);
    }

    @Override
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull cryptid.ibe.domain.PrivateKey privateKey) throws IllegalArgumentException {
        CipherTextTuple cipherTextTuple = SerializationUtils.deserialize(encryptedSegment);
        Optional<String> optionalDecrypted = ibe.decrypt(privateKey, cipherTextTuple);
        // TODO: cf. TODO in encrypt method: same reason here.
        if (optionalDecrypted.isPresent()) return SerializationUtils.serialize(optionalDecrypted.get());
        throw new IllegalArgumentException("Encrypted segment could not be decrypted.");
    }

    /**
     * Method to convert identifier to a {@link PrivateKey}, for the IBE PKG running on this node.
     * @param   identifier
     *          The IBE identifier.
     * @return  The IBE {@link PrivateKey} associated with the IBE identifier for the IBE PKG running on this node.
     */
    public static PrivateKey convertIdentifierToPrivateKey(@NotNull String identifier) {
        return ibe.extract(identifier);
    }
}
