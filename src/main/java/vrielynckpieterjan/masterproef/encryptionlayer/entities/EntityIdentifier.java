package vrielynckpieterjan.masterproef.encryptionlayer.entities;

import com.google.common.hash.Hashing;
import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.ECCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Abstract class representing an entity identifier.
 *
 * @param <RSAKeyType>           The subtype of the {@link Key} used to represent the RSA part of the identifier.
 * @param <IBEEncryptionKeyType> The type used to represent the IBE part of the identifier.
 */
public abstract class EntityIdentifier<RSAKeyType extends Key,
        IBEEncryptionKeyType> implements Exportable {

    private final RSAKeyType rsaIdentifier;
    private final IBEEncryptionKeyType ibeIdentifier;
    private final String namespaceServiceProviderEmailAddressUserConcatenation;

    /**
     * Constructor for the {@link EntityIdentifier} class.
     *
     * @param rsaIdentifier                                         The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param namespaceServiceProviderEmailAddressUserConcatenation A concatenation of the namespace and the e-mail address of the user.
     * @param hashConcatenation                                     Boolean indicating if the namespaceServiceProviderEmailAddressUserConcatenation parameter should yet be hashed.
     */
    protected EntityIdentifier(@NotNull RSAKeyType rsaIdentifier,
                               @NotNull IBEEncryptionKeyType ibeIdentifier,
                               @NotNull String namespaceServiceProviderEmailAddressUserConcatenation,
                               boolean hashConcatenation) {
        this.rsaIdentifier = rsaIdentifier;
        this.ibeIdentifier = ibeIdentifier;
        this.namespaceServiceProviderEmailAddressUserConcatenation = (hashConcatenation) ? Hashing.sha512().hashString(
                namespaceServiceProviderEmailAddressUserConcatenation, StandardCharsets.UTF_8).toString() :
                namespaceServiceProviderEmailAddressUserConcatenation;
    }

    /**
     * Constructor for the {@link EntityIdentifier} class.
     *
     * @param rsaIdentifier                                         The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param namespaceServiceProviderEmailAddressUserConcatenation A concatenation of the namespace and the e-mail address of the user.
     *                                                              This value should not be hashed yet.
     */
    @Deprecated
    protected EntityIdentifier(@NotNull RSAKeyType rsaIdentifier,
                               @NotNull IBEEncryptionKeyType ibeIdentifier,
                               @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        this(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, true);
    }

    /**
     * Static method to generate the combination of a {@link PublicEntityIdentifier} and its
     * {@link PrivateEntityIdentifier} counterpart.
     *
     * @param namespaceEmailAddressConcatenation The concatenation of the namespace and the e-mail address of the user, which shouldn't be hashed yet.
     *                                           A hashed version (SHA-512) of this concatenation can be used as the {@link vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier}
     *                                           to store the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation}
     *                                           of the generated user with in the {@link vrielynckpieterjan.masterproef.storagelayer.StorageLayer}.
     * @return The combination as a {@link Pair}.
     */
    public static Pair<PrivateEntityIdentifier, PublicEntityIdentifier> generateEntityIdentifierPair(
            @NotNull String namespaceEmailAddressConcatenation) {
        final var keyPair = new AtomicReference<KeyPair>();
        final var PKG = new AtomicReference<Pair<PublicParameters, BigInteger>>();

        var rsaThread = new Thread(() -> keyPair.set(ECCipherEncryptedSegment.generateKeyPair()));
        var ibeThread = new Thread(() -> PKG.set(IBEDecryptableSegment.generatePKG()));

        rsaThread.start();
        ibeThread.start();
        try {
            ibeThread.join();
            rsaThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.exit(1);
        }

        var rsaKeyPair = keyPair.get();
        var ibePKG = PKG.get();

        PrivateEntityIdentifier privateEntityIdentifier = new PrivateEntityIdentifier(rsaKeyPair.getPublic(),
                ibePKG, namespaceEmailAddressConcatenation);
        PublicEntityIdentifier publicEntityIdentifier = new PublicEntityIdentifier(
                rsaKeyPair.getPrivate(), ibePKG.getLeft(),
                namespaceEmailAddressConcatenation);
        return new ImmutablePair<>(privateEntityIdentifier, publicEntityIdentifier);
    }

    /**
     * Getter for the {@link Key} used to represent the RSA part of the identifier.
     *
     * @return The RSA {@link Key}.
     */
    public RSAKeyType getRSAIdentifier() {
        return rsaIdentifier;
    }

    /**
     * Getter for the IBE part of the identifier.
     *
     * @return The IBE part of the identifier.
     */
    public IBEEncryptionKeyType getIBEIdentifier() {
        return ibeIdentifier;
    }

    /**
     * Getter for the hashed version of the concatenation of the namespace and the e-mail address of the user.
     *
     * @return The hash.
     */
    public String getNamespaceServiceProviderEmailAddressUserConcatenation() {
        return namespaceServiceProviderEmailAddressUserConcatenation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EntityIdentifier that = (EntityIdentifier) o;

        return rsaIdentifier.equals(that.rsaIdentifier) &&
                ibeIdentifier.equals(that.ibeIdentifier) &&
                namespaceServiceProviderEmailAddressUserConcatenation.equals(that.namespaceServiceProviderEmailAddressUserConcatenation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rsaIdentifier, ibeIdentifier,
                namespaceServiceProviderEmailAddressUserConcatenation);
    }

    @Override
    public String toString() {
        return namespaceServiceProviderEmailAddressUserConcatenation;
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(rsaIdentifier);
        objectOutputStream.flush();
        byte[] rsaIdentifierAsByteArray = byteArrayOutputStream.toByteArray();

        byteArrayOutputStream = new ByteArrayOutputStream();
        objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(ibeIdentifier);
        objectOutputStream.flush();
        byte[] ibeIdentifierAsByteArray = byteArrayOutputStream.toByteArray();

        ByteBuffer byteBuffer = ByteBuffer.allocate(rsaIdentifierAsByteArray.length + ibeIdentifierAsByteArray.length +
                namespaceServiceProviderEmailAddressUserConcatenation.length() + 4 * 2);
        byteBuffer.putInt(rsaIdentifierAsByteArray.length);
        byteBuffer.put(rsaIdentifierAsByteArray);
        byteBuffer.putInt(ibeIdentifierAsByteArray.length);
        byteBuffer.put(ibeIdentifierAsByteArray);
        byteBuffer.put(namespaceServiceProviderEmailAddressUserConcatenation.getBytes(StandardCharsets.UTF_8));

        return byteBuffer.array();
    }
}
