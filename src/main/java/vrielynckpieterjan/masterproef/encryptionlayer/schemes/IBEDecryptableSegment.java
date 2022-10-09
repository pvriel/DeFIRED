package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

import cryptid.ellipticcurve.point.affine.AffinePoint;
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
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Class representing an IBE {@link DecryptableSegment}.
 *
 * @param <DecryptedObjectType> The type of the decrypted version of the {@link IBEDecryptableSegment}.
 */
public class IBEDecryptableSegment<DecryptedObjectType extends Serializable>
        implements DecryptableSegment<DecryptedObjectType, Pair<PublicParameters, PrivateKey>> {

    private final static Logger logger = Logger.getLogger(IBEDecryptableSegment.class.getName());
    static IbeComponentFactory componentFactory;
    private static SecureRandom secureRandom;
    private static SolinasPrimeFactory solinasPrimeFactory;
    private static GenerationStrategyFactory<Mod3GenerationStrategy> generationStrategyFactory;
    private static IbeInitializer initializer;

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
     * @param encryptedSegment The (already) encrypted segment.
     */
    protected IBEDecryptableSegment(@NotNull CipherTextTuple encryptedSegment) {
        this.encryptedSegment = encryptedSegment;
    }

    /**
     * Constructor for the {@link IBEDecryptableSegment} class.
     *
     * @param originalObject             The original object to encrypt.
     * @param publicParametersStringPair The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
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
     *
     * @param originalObject         The original object to encrypt.
     * @param publicEntityIdentifier A {@link PublicEntityIdentifier} to encrypt the original object with.
     * @param usedIBEIdentifier      The IBE identifier used to encrypt this specific object with.
     * @throws IllegalArgumentException If an invalid IBE identifier or {@link PublicEntityIdentifier} was provided.
     */
    public IBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicEntityIdentifier publicEntityIdentifier,
                                 @NotNull String usedIBEIdentifier) throws IllegalArgumentException {
        this(originalObject, new ImmutablePair<>(publicEntityIdentifier.getIBEIdentifier(), usedIBEIdentifier));
    }

    /**
     * Constructor for the {@link IBEDecryptableSegment} class.
     *
     * @param originalObject         The original object to encrypt.
     * @param publicEntityIdentifier A {@link PublicEntityIdentifier} to encrypt the original object with.
     * @param usedIBEIdentifier      The IBE identifier (as a {@link RTreePolicy} instance) used to encrypt this specific object with.
     * @throws IllegalArgumentException If an invalid IBE identifier or {@link PublicEntityIdentifier} was provided.
     */
    public IBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicEntityIdentifier publicEntityIdentifier,
                                 @NotNull RTreePolicy usedIBEIdentifier) throws IllegalArgumentException {
        this(originalObject, publicEntityIdentifier, usedIBEIdentifier.toString());
    }

    /**
     * Method to generate an IBE encryption PKG.
     *
     * @return A {@link Pair}, containing a {@link PublicParameters} to represent the public parameters of the PKG
     * and a {@link BigInteger} to represent the master secret of the PKG.
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

    public static @NotNull PrivateKey generatePrivateKey(@NotNull PrivateEntityIdentifier privateEntityIdentifier,
                                                         @NotNull String id) throws IllegalArgumentException {
        try {
            PrivateKeyGenerator privateKeyGenerator = componentFactory.obtainPrivateKeyGenerator(
                    privateEntityIdentifier.getIBEIdentifier().getLeft(), privateEntityIdentifier.getIBEIdentifier().getRight());
            return privateKeyGenerator.extract(id);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Method to convert a {@link Serializable} to a readable String.
     *
     * @param serializable The {@link Serializable}.
     * @return A base64 String.
     * @throws IOException If the String could not be converted.
     */
    public static @NotNull String convertSerializableToString(@NotNull Serializable serializable)
            throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(serializable);
        objectOutputStream.close();
        return Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
    }

    public static @NotNull PrivateKeyGenerator obtainPKG(@NotNull PrivateEntityIdentifier privateEntityIdentifier) throws ComponentConstructionException {
        return obtainPKG(privateEntityIdentifier.getIBEIdentifier().getLeft(), privateEntityIdentifier.getIBEIdentifier().getRight());
    }

    private static @NotNull PrivateKeyGenerator obtainPKG(@NotNull PublicParameters publicParameters, @NotNull BigInteger masterSecret) throws ComponentConstructionException {
        return componentFactory.obtainPrivateKeyGenerator(publicParameters, masterSecret);
    }

    @NotNull
    public static IBEDecryptableSegment deserialize(@NotNull ByteBuffer byteBuffer) {
        byte[] xArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(xArray);
        byte[] yArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(yArray);
        byte[] v = new byte[byteBuffer.getInt()];
        byteBuffer.get(v);
        byte[] w = new byte[byteBuffer.remaining()];
        byteBuffer.get(w);

        BigInteger x = new BigInteger(xArray);
        BigInteger y = new BigInteger(yArray);
        AffinePoint u = new AffinePoint(x, y);

        CipherTextTuple cipherTextTuple = new CipherTextTuple(u, v, w);
        return new IBEDecryptableSegment(cipherTextTuple);
    }

    /**
     * Method to convert a readble String to a DecryptedObjectType instance.
     *
     * @param string The String.
     * @return A DecryptedObjectType instance.
     * @throws IOException            If the String could not be converted to a DecryptedObjectType instance.
     * @throws ClassNotFoundException If the String could not be converted to a DecryptedObjectType instance.
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
     *
     * @param originalObject             The original object to encrypt.
     * @param publicParametersStringPair A {@link Pair}, containing the necessary objects to encrypt the original object with.
     * @return The encrypted object as a {@link CipherTextTuple}.
     * @throws IllegalArgumentException If the original object could not be encrypted using the provided arguments.
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

    public @NotNull DecryptedObjectType decrypt(@NotNull IbeClient ibeClient, @NotNull PrivateKey privateKey) throws IllegalArgumentException {
        try {
            String decryptedObjectAsString = ibeClient.decrypt(privateKey, encryptedSegment).get();
            return convertStringToDecryptedObjectType(decryptedObjectAsString);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public @NotNull DecryptedObjectType decrypt(@NotNull PublicParameters publicParameters, @NotNull PrivateKey privateKey) throws IllegalArgumentException {
        try {
            IbeClient ibeClient = componentFactory.obtainClient(publicParameters);
            return decrypt(ibeClient, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public @NotNull DecryptedObjectType decrypt(@NotNull PublicParameters publicParameters, @NotNull BigInteger masterSecret,
                                                @NotNull String id) throws IllegalArgumentException {
        try {
            PrivateKeyGenerator privateKeyGenerator = componentFactory.obtainPrivateKeyGenerator(publicParameters, masterSecret);
            PrivateKey privateKey = privateKeyGenerator.extract(id);
            return decrypt(publicParameters, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public @NotNull DecryptedObjectType decrypt(@NotNull PublicParameters publicParameters, @NotNull BigInteger masterSecret,
                                                @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        return decrypt(publicParameters, masterSecret, rTreePolicy.toString());
    }

    @Override
    public @NotNull DecryptedObjectType decrypt(@NotNull Pair<PublicParameters, PrivateKey> decryptionPair) throws IllegalArgumentException {
        return decrypt(decryptionPair.getLeft(), decryptionPair.getRight());
    }

    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier,
                                                @NotNull String id) throws IllegalArgumentException {
        return decrypt(privateEntityIdentifier.getIBEIdentifier().getLeft(),
                privateEntityIdentifier.getIBEIdentifier().getRight(),
                id);
    }

    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier,
                                                @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        return decrypt(privateEntityIdentifier, rTreePolicy.toString());
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

    @Override
    public byte[] serialize() {
        AffinePoint u = encryptedSegment.getCipherU();

        BigInteger x = u.getX();
        byte[] xArray = x.toByteArray();
        BigInteger y = u.getY();
        byte[] yArray = y.toByteArray();
        byte[] v = encryptedSegment.getCipherV();
        byte[] w = encryptedSegment.getCipherW();

        ByteBuffer byteBuffer = ByteBuffer.allocate(xArray.length + yArray.length + v.length + w.length + 4 * 3);
        for (byte[] array : new byte[][]{xArray, yArray, v}) {
            byteBuffer.putInt(array.length);
            byteBuffer.put(array);
        }
        byteBuffer.put(w);

        return byteBuffer.array();
    }
}
