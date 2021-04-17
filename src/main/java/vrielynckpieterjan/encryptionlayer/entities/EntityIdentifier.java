package vrielynckpieterjan.encryptionlayer.entities;

import com.google.common.hash.Hashing;
import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.encryptionlayer.schemes.RSACipherEncryptedSegment;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.util.Objects;

/**
 * Abstract class representing an entity identifier.
 * @param   <RSAKeyType>
 *          The subtype of the {@link Key} used to represent the RSA part of the identifier.
 * @param   <IBEEncryptionKeyType>
 *          The type used to represent the IBE part of the identifier.
 */
public abstract class EntityIdentifier<RSAKeyType extends Key,
        IBEEncryptionKeyType> implements Serializable {

    private final RSAKeyType rsaIdentifier;
    private final IBEEncryptionKeyType ibeIdentifier;
    private final String namespaceServiceProviderEmailAddressUserConcatenation;

    /**
     * Constructor for the {@link EntityIdentifier} class.
     * @param   rsaIdentifier
     *          The {@link Key} used to represent the RSA part of the identifier.
     * @param   ibeIdentifier
     *          The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     *          This value should not be hashed yet.
     */
    protected EntityIdentifier(@NotNull RSAKeyType rsaIdentifier,
                            @NotNull IBEEncryptionKeyType ibeIdentifier,
                            @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        this.rsaIdentifier = rsaIdentifier;
        this.ibeIdentifier = ibeIdentifier;
        this.namespaceServiceProviderEmailAddressUserConcatenation = Hashing.sha512().hashString(
                namespaceServiceProviderEmailAddressUserConcatenation, StandardCharsets.UTF_8).toString();
    }

    /**
     * Getter for the {@link Key} used to represent the RSA part of the identifier.
     * @return  The RSA {@link Key}.
     */
    public RSAKeyType getRSAIdentifier() {
        return rsaIdentifier;
    }

    /**
     * Getter for the IBE part of the identifier.
     * @return  The IBE part of the identifier.
     */
    public IBEEncryptionKeyType getIBEIdentifier() {
        return ibeIdentifier;
    }

    /**
     * Getter for the hashed version of the concatenation of the namespace and the e-mail address of the user.
     * @return  The hash.
     */
    public String getNamespaceServiceProviderEmailAddressUserConcatenation() {
        return namespaceServiceProviderEmailAddressUserConcatenation;
    }

    /**
     * Static method to generate the combination of a {@link PublicEntityIdentifier} and its
     * {@link PrivateEntityIdentifier} counterpart.
     * @param   namespaceEmailAddressConcatenation
     *          The concatenation of the namespace and the e-mail address of the user, which shouldn't be hashed yet.
     *          A hashed version (SHA-512) of this concatenation can be used as the {@link vrielynckpieterjan.storagelayer.StorageElementIdentifier}
     *          to store the {@link vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation}
     *          of the generated user with in the {@link vrielynckpieterjan.storagelayer.StorageLayer}.
     * @return  The combination as a {@link Pair}.
     */
    public static Pair<PrivateEntityIdentifier, PublicEntityIdentifier> generateEntityIdentifierPair(
            @NotNull String namespaceEmailAddressConcatenation) {
        KeyPair rsaKeyPair = RSACipherEncryptedSegment.generateKeyPair();
        Pair<PublicParameters, BigInteger> ibePKG = IBEDecryptableSegment.generatePKG();

        PrivateEntityIdentifier privateEntityIdentifier = new PrivateEntityIdentifier(rsaKeyPair.getPublic(),
                ibePKG, namespaceEmailAddressConcatenation);
        PublicEntityIdentifier publicEntityIdentifier = new PublicEntityIdentifier(
                rsaKeyPair.getPrivate(), ibePKG.getLeft(),
                namespaceEmailAddressConcatenation);
        return new ImmutablePair<>(privateEntityIdentifier, publicEntityIdentifier);
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
}
