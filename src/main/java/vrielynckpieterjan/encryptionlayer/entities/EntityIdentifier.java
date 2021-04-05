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
 * Abstract class representing a public / private entity identifier.
 * @param   <RSAEncryptionKeyType>
 *          The subtype of the {@link Key} used to represent the first RSA part of the identifier.
 * @param   <RSADecryptionKeyType>
 *          The subtype of the {@link Key} used to represent the second RSA part of the identifier.
 * @param   <IBEEncryptionKeyType>
 *          The type used to represent the IBE part of the identifier.
 * @param   <WIBEEncryptionKeyType>
 *          The type used to represent the WIBE part of the identifier.
 */
public abstract class EntityIdentifier<RSAEncryptionKeyType extends Key, RSADecryptionKeyType extends Key,
        IBEEncryptionKeyType, WIBEEncryptionKeyType> implements Serializable {

    private final RSAEncryptionKeyType rsaIdentifierOne;
    private final RSADecryptionKeyType rsaIdentifierTwo;
    private final IBEEncryptionKeyType ibeIdentifier;
    private final WIBEEncryptionKeyType wibeIdentifier;
    private final String namespaceServiceProviderEmailAddressUserConcatenation;

    /**
     * Constructor for the {@link EntityIdentifier} class.
     * @param   rsaEncryptionIdentifier
     *          The {@link Key} used to represent the first RSA part of the identifier.
     * @param   rsaDecryptionIdentifier
     *          The {@link Key} used to represent the second RSA part of the identifier.
     * @param   ibeIdentifier
     *          The IBE part of the identifier.
     * @param   wibeIdentifier
     *          The WIBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     */
    public EntityIdentifier(@NotNull RSAEncryptionKeyType rsaEncryptionIdentifier,
                            @NotNull RSADecryptionKeyType rsaDecryptionIdentifier,
                            @NotNull IBEEncryptionKeyType ibeIdentifier,
                            @NotNull WIBEEncryptionKeyType wibeIdentifier,
                            @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        this.rsaIdentifierOne = rsaEncryptionIdentifier;
        this.rsaIdentifierTwo = rsaDecryptionIdentifier;
        this.ibeIdentifier = ibeIdentifier;
        this.wibeIdentifier = wibeIdentifier;
        this.namespaceServiceProviderEmailAddressUserConcatenation = Hashing.sha512().hashString(
                namespaceServiceProviderEmailAddressUserConcatenation, StandardCharsets.UTF_8).toString();
    }

    /**
     * Getter for the {@link Key} used to represent the first RSA part of the identifier.
     * @return  The RSA {@link Key}.
     */
    public RSAEncryptionKeyType getRSAEncryptionIdentifier() {
        return rsaIdentifierOne;
    }

    /**
     * Getter for the {@link Key} used to represent the second RSA part of the identifier.
     * @return  The RSA {@link Key}.
     */
    public RSADecryptionKeyType getRSADecryptionIdentifier() {return rsaIdentifierTwo;}

    /**
     * Getter for the IBE part of the identifier.
     * @return  The IBE part of the identifier.
     */
    public IBEEncryptionKeyType getIBEIdentifier() {
        return ibeIdentifier;
    }

    /**
     * Getter for the WIBE part of the identifier.
     * @return  The WIBE part of the identifier.
     */
    public WIBEEncryptionKeyType getWIBEIdentifier() {
        return wibeIdentifier;
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
     *          The concatenation of the namespace and the e-mail address of the user.
     *          A hashed version (SHA-512) of this concatenation can be used as the {@link vrielynckpieterjan.storagelayer.StorageElementIdentifier}
     *          to store the {@link vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation}
     *          of the generated user with in the {@link vrielynckpieterjan.storagelayer.StorageLayer}.
     * @return  The combination as a {@link Pair}.
     */
    public static Pair<PrivateEntityIdentifier, PublicEntityIdentifier> generateEntityIdentifierPair(
            @NotNull String namespaceEmailAddressConcatenation) {
        KeyPair rsaKeyPairOne = RSACipherEncryptedSegment.generateKeyPair();
        KeyPair rsaKeyPairTwo = RSACipherEncryptedSegment.generateKeyPair();
        Pair<PublicParameters, BigInteger> ibePKG = IBEDecryptableSegment.generatePKG();
        Pair<PublicParameters, BigInteger> wibePKG = IBEDecryptableSegment.generatePKG();

        PrivateEntityIdentifier privateEntityIdentifier = new PrivateEntityIdentifier(
                rsaKeyPairOne.getPrivate(), rsaKeyPairTwo.getPublic(), ibePKG, wibePKG,
                namespaceEmailAddressConcatenation);
        PublicEntityIdentifier publicEntityIdentifier = new PublicEntityIdentifier(
                rsaKeyPairOne.getPublic(), rsaKeyPairTwo.getPrivate(), ibePKG.getLeft(), wibePKG.getLeft(),
                namespaceEmailAddressConcatenation);
        return new ImmutablePair<>(privateEntityIdentifier, publicEntityIdentifier);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EntityIdentifier that = (EntityIdentifier) o;
        return rsaIdentifierOne.equals(that.rsaIdentifierOne) && rsaIdentifierTwo.equals(that.rsaIdentifierTwo) &&
                ibeIdentifier.equals(that.ibeIdentifier) && wibeIdentifier.equals(that.wibeIdentifier) &&
                namespaceServiceProviderEmailAddressUserConcatenation.equals(that.namespaceServiceProviderEmailAddressUserConcatenation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rsaIdentifierOne, rsaIdentifierTwo, ibeIdentifier, wibeIdentifier,
                namespaceServiceProviderEmailAddressUserConcatenation);
    }

    @Override
    public String toString() {
        return namespaceServiceProviderEmailAddressUserConcatenation;
    }
}
