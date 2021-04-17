package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

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
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;

import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Class representing an IBE {@link DecryptableSegment}.
 * @param       <DecryptedObjectType>
 *              The type of the decrypted version of the {@link IBEDecryptableSegment}.
 */
public class IBEDecryptableSegment<DecryptedObjectType extends Serializable>
        implements DecryptableSegment<DecryptedObjectType, Triple<PublicParameters, BigInteger, String>> {

    private final static Logger logger = Logger.getLogger(IBEDecryptableSegment.class.getName());
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

    private final CipherTextTuple encryptedSegment;

    /**
     * Constructor for the {@link IBEDecryptableSegment} class.
     *
     * @param originalObject                The original object to encrypt.
     * @param publicParametersStringPair    The key to encrypt the original object with.
     * @throws IllegalArgumentException     If an illegal key was provided.
     */
    public IBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull Pair<PublicParameters, String> publicParametersStringPair)
            throws IllegalArgumentException {
        /*
        Convert the original object to a String first.
        This is required by the underlying IBE encryption library.
         */
        String convertedOriginalObject;
        try {
            convertedOriginalObject = convertSerializableToString(originalObject);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }

        // Actual encryption part.
        encryptedSegment = encrypt(convertedOriginalObject, publicParametersStringPair);
    }

    /**
     * Constructor for the {@link IBEDecryptableSegment} class.
     * @param   originalObject
     *          The original object to encrypt.
     * @param   publicEntityIdentifier
     *          A {@link PublicEntityIdentifier} to encrypt the original object with.
     * @param   usedIBEIdentifier
     *          The IBE identifier used to encrypt this specific object with.
     * @throws  IllegalArgumentException
     *          If an invalid IBE identifier or {@link PublicEntityIdentifier} was provided.
     */
    public IBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicEntityIdentifier publicEntityIdentifier,
                                 @NotNull String usedIBEIdentifier) throws IllegalArgumentException {
        this(originalObject, new ImmutablePair<>(publicEntityIdentifier.getIBEIdentifier(), usedIBEIdentifier));
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

    /**
     * Method to convert a {@link Serializable} to a readable String.
     * @param   serializable
     *          The {@link Serializable}.
     * @return  A base64 String.
     * @throws  IOException
     *          If the String could not be converted.
     */
    public static @NotNull String convertSerializableToString(@NotNull Serializable serializable)
            throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(serializable);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    /**
     * Method to convert a readble String to a DecryptedObjectType instance.
     * @param   string
     *          The String.
     * @return  A DecryptedObjectType instance.
     * @throws  IOException
     *          If the String could not be converted to a DecryptedObjectType instance.
     * @throws  ClassNotFoundException
     *          If the String could not be converted to a DecryptedObjectType instance.
     */
    private @NotNull DecryptedObjectType convertStringToDecryptedObjectType(@NotNull String string)
            throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(string);
        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(data));
        DecryptedObjectType decryptedObject = (DecryptedObjectType) objectInputStream.readObject();
        objectInputStream.close();
        return decryptedObject;
    }

    /**
     * Method to encrypt a String using the provided {@link PublicParameters} instance and identifier.
     * @param   originalObject
     *          The original object to encrypt.
     * @param   publicParametersStringPair
     *          A {@link Pair}, containing the necessary objects to encrypt the original object with.
     * @return  The encrypted object as a {@link CipherTextTuple}.
     * @throws  IllegalArgumentException
     *          If the original object could not be encrypted using the provided arguments.
     */
    private CipherTextTuple encrypt(@NotNull String originalObject,
                             @NotNull Pair<PublicParameters, String> publicParametersStringPair)
            throws IllegalArgumentException {
        try {
            // Construct the necessary part of the PKG to encrypt the String.
            IbeClient ibeClient = componentFactory.obtainClient(publicParametersStringPair.getLeft());
            // Actual encryption part.
            CipherTextTuple cipherTextTuple = ibeClient.encrypt(originalObject, publicParametersStringPair.getRight());
            return cipherTextTuple;
        } catch (ComponentConstructionException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public @NotNull DecryptedObjectType decrypt(@NotNull Triple<PublicParameters, BigInteger, String> publicParametersBigIntegerStringTriple)
            throws IllegalArgumentException {
        // Decryption part.
        String decryptedObjectAsString;
        try {
            // Construct the necessary part of the PKG to decrypt the CipherTextTuple.
            var ibeClientAndPKG = obtainIBEClientAndPKG(publicParametersBigIntegerStringTriple.getLeft(),
                    publicParametersBigIntegerStringTriple.getMiddle());
            var ibeClient = ibeClientAndPKG.getLeft();
            var privateKeyGenerator = ibeClientAndPKG.getRight();
            // Actual decryption part.
            PrivateKey privateKey = privateKeyGenerator.extract(publicParametersBigIntegerStringTriple.getRight());
            Optional<String> optionalDecryptedString = ibeClient.decrypt(privateKey, encryptedSegment);

            if (optionalDecryptedString.isEmpty())
                throw new IllegalArgumentException("IBEEncryptedSegment could not be decrypted using the provided arguments.");
            decryptedObjectAsString =  optionalDecryptedString.get();
        } catch (ComponentConstructionException e) {
            throw new IllegalArgumentException(e);
        }

        // Convert String to original object type and return.
       try {
           return convertStringToDecryptedObjectType(decryptedObjectAsString);
       } catch (IOException | ClassNotFoundException e) {
           throw new IllegalArgumentException(e);
       }
    }

    /**
     * Method to obtain the {@link IbeClient} and {@link PrivateKeyGenerator} for a given {@link PublicParameters}
     * and {@link BigInteger} instance.
     * @param   publicParameters
     *          The {@link PublicParameters}.
     * @param   masterSecret
     *          The {@link BigInteger}.
     * @return  An {@link ImmutablePair}, containing the {@link IbeClient} and {@link PrivateKeyGenerator} instances.
     * @throws  ComponentConstructionException
     *          If one of the provided arguments is invalid.
     */
    private @NotNull Pair<IbeClient, PrivateKeyGenerator> obtainIBEClientAndPKG(@NotNull PublicParameters publicParameters,
                                                                                @NotNull BigInteger masterSecret)
            throws ComponentConstructionException {
        IbeClient ibeClient = componentFactory.obtainClient(publicParameters);
        PrivateKeyGenerator privateKeyGenerator = componentFactory.obtainPrivateKeyGenerator(publicParameters, masterSecret);
        return new ImmutablePair<>(ibeClient, privateKeyGenerator);
    }

    /**
     * Method to decrypt the {@link IBEDecryptableSegment}.
     * @param   publicParameters
     *          The {@link PublicParameters} of the IBE PKG.
     * @param   bigInteger
     *          The master secret as a {@link BigInteger} for the IBE PKG.
     * @param   policy
     *          The {@link RTreePolicy} instance to decrypt this {@link IBEDecryptableSegment} with.
     * @return  The decrypted an deserialized segment.
     * @throws  IllegalArgumentException
     *          If the {@link IBEDecryptableSegment} could not be decrypted using the provided arguments.
     * @apiNote
     *          This method does not try to decrypt the {@link IBEDecryptableSegment} using the possible policies
     *          for the parent directories of the provided {@link RTreePolicy} argument.
     *          If this is required however, it's the caller's responsibility to call this method for each variation.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PublicParameters publicParameters, @NotNull BigInteger bigInteger,
                                                @NotNull RTreePolicy policy)
            throws IllegalArgumentException {
        return this.decrypt(new ImmutableTriple<>(publicParameters, bigInteger, policy.toString()));
    }

    /**
     * Method to decrypt the {@link IBEDecryptableSegment}.
     * @param   privateEntityIdentifier
     *          The {@link PrivateEntityIdentifier} to decrypt the {@link IBEDecryptableSegment} with.
     * @param   ibeIdentifier
     *          The IBE identifier to decrypt the {@link IBEDecryptableSegment} with.
     * @return  The decrypted and deserialized {@link IBEDecryptableSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key or IBE identifier can't be used to decrypt the {@link IBEDecryptableSegment}.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier, @NotNull String ibeIdentifier)
            throws IllegalArgumentException {
        return this.decrypt(new ImmutableTriple<>(privateEntityIdentifier.getIBEIdentifier().getLeft(),
                privateEntityIdentifier.getIBEIdentifier().getRight(), ibeIdentifier));
    }

    /**
     * Method to decrypt the {@link IBEDecryptableSegment}.
     * @param   privateEntityIdentifier
     *          The {@link PrivateEntityIdentifier} to decrypt this instance with.
     * @param   policy
     *          The {@link RTreePolicy} instance to decrypt this {@link IBEDecryptableSegment} with.
     * @return  The decrypted and deserialized segment.
     * @throws  IllegalArgumentException
     *          If the provided arguments could not be used to decrypt this {@link IBEDecryptableSegment} with.
     * @apiNote
     *          This method does not try to decrypt the {@link IBEDecryptableSegment} using the possible policies
     *          for the parent directories of the provided {@link RTreePolicy} argument.
     *          If this is required however, it's the caller's responsibility to call this method for each variation.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier, @NotNull RTreePolicy policy)
        throws IllegalArgumentException {
        return this.decrypt(privateEntityIdentifier, policy.toString());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IBEDecryptableSegment<?> that = (IBEDecryptableSegment<?>) o;
        return encryptedSegment.equals(that.encryptedSegment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedSegment);
    }
}
