package vrielynckpieterjan.encryptionlayer;

import cryptid.ellipticcurve.point.affine.generator.GenerationStrategyFactory;
import cryptid.ellipticcurve.point.affine.generator.Mod3GenerationStrategy;
import cryptid.ibe.IbeClient;
import cryptid.ibe.IbeComponentFactory;
import cryptid.ibe.IbeInitializer;
import cryptid.ibe.PrivateKeyGenerator;
import cryptid.ibe.bonehfranklin.BonehFranklinIbeComponentFactoryImpl;
import cryptid.ibe.bonehfranklin.BonehFranklinIbeInitializer;
import cryptid.ibe.domain.*;
import cryptid.ibe.exception.ComponentConstructionException;
import cryptid.ibe.exception.SetupException;
import cryptid.ibe.util.SolinasPrimeFactory;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Class representing an IBE {@link EncryptedSegment}.
 * @implSpec    Unlike the other {@link EncryptedSegment} implementations,
 *              this class can only be used to encrypt Strings due to the limitations
 *              of the used IBE encryption library.
 */
public class IBEEncryptedSegment
        extends EncryptedSegment<String, Pair<PublicParameters, String>, Triple<PublicParameters, BigInteger, String>> {

    private final static Logger logger = Logger.getLogger(IBEEncryptedSegment.class.getName());
    private static SecureRandom secureRandom;
    private static SolinasPrimeFactory solinasPrimeFactory;
    private static GenerationStrategyFactory<Mod3GenerationStrategy> generationStrategyFactory;
    private static IbeInitializer initializer;
    static IbeComponentFactory componentFactory;

    static {
        try {
            secureRandom = SecureRandom.getInstanceStrong();
            solinasPrimeFactory = new SolinasPrimeFactory(secureRandom);
            generationStrategyFactory =
                    ellipticCurve -> new Mod3GenerationStrategy(ellipticCurve, secureRandom);
            initializer = new BonehFranklinIbeInitializer(
                    secureRandom, solinasPrimeFactory, generationStrategyFactory);
            componentFactory = new BonehFranklinIbeComponentFactoryImpl(secureRandom);
        } catch (NoSuchAlgorithmException e) {
            logger.severe(String.format("The SecureRandom instance could not be initialized (reason: %s). Due" +
                    " to the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Constructor for the {@link IBEEncryptedSegment} class.
     *
     * @param originalObject             The original object to encrypt.
     * @param publicParametersStringPair The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public IBEEncryptedSegment(@NotNull String originalObject, @NotNull Pair<PublicParameters, String> publicParametersStringPair) throws IllegalArgumentException {
        super(originalObject, publicParametersStringPair);
    }

    /**
     * Method to generate an IBE encryption PKG.
     * @return  A {@link Pair}, containing a {@link PublicParameters} to represent the public parameters of the PKG
     *          and a {@link BigInteger} to represent the master secret of the PKG.
     */
    public static Pair<PublicParameters, BigInteger> generatePKG() {
        try {
            IbeSetup setup = initializer.setup(SecurityLevel.LOWEST);
            return new ImmutablePair<>(setup.getPublicParameters(), setup.getMasterSecret());
        } catch (SetupException e) {
            logger.severe(String.format("No IBE encryption PKGs could be generated (reason: %s). Due" +
                    " to the severity of this problem, the program will now exit.", e));
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject,
                             @NotNull Pair<PublicParameters, String> publicParametersStringPair)
            throws IllegalArgumentException {
        // TODO: optimize this. serializedOriginalObject is already a serialized String.
        String originalObject = SerializationUtils.deserialize(serializedOriginalObject);

        try {
            // Construct the necessary part of the PKG to encrypt the String.
            IbeClient ibeClient = componentFactory.obtainClient(publicParametersStringPair.getLeft());
            // Actual encryption part.
            CipherTextTuple cipherTextTuple = ibeClient.encrypt(originalObject, publicParametersStringPair.getRight());
            return SerializationUtils.serialize(cipherTextTuple);
        } catch (ComponentConstructionException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull Triple<PublicParameters, BigInteger, String> publicParametersBigIntegerStringTriple) throws IllegalArgumentException {
        CipherTextTuple cipherTextTuple = SerializationUtils.deserialize(encryptedSegment);

        try {
            // Construct the necessary part of the PKG to decrypt the CipherTextTuple.
            IbeClient ibeClient = componentFactory.obtainClient(publicParametersBigIntegerStringTriple.getLeft());
            PrivateKeyGenerator privateKeyGenerator = componentFactory.obtainPrivateKeyGenerator(
                    publicParametersBigIntegerStringTriple.getLeft(), publicParametersBigIntegerStringTriple.getMiddle());
            // Actual decryption part.
            PrivateKey privateKey = privateKeyGenerator.extract(publicParametersBigIntegerStringTriple.getRight());
            Optional<String> optionalDecryptedString = ibeClient.decrypt(privateKey, cipherTextTuple);

            if (optionalDecryptedString.isEmpty())
                throw new IllegalArgumentException("IBEEncryptedSegment could not be decrypted using the provided arguments.");
            String decryptedString = optionalDecryptedString.get();
            return SerializationUtils.serialize(decryptedString);
        } catch (ComponentConstructionException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
