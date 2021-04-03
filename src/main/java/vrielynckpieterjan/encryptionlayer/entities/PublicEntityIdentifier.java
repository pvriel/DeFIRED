package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Class representing a public {@link EntityIdentifier}.
 */
public class PublicEntityIdentifier
        extends EntityIdentifier<PublicKey, PrivateKey, PublicParameters, PublicParameters> {

    private final String namespaceServiceProviderEmailAddressUserConcatenation;

    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     * @param   rsaEncryptionIdentifier
     *          The {@link Key} used to represent the first RSA part of the identifier.
     * @param   rsaDecryptionIdentifier
     *          The {@link Key} used to represent the second RSA part of the identifier.
     * @param   ibeIdentifier
     *          The IBE part of the identifier.
     * @param   wibeIdentifier
     *          The WIBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace of the cloud storage service provider and the e-mail address of the user.
     *          This concatenation is used to store the user's {@link NamespaceAttestation}
     *          in the {@link vrielynckpieterjan.storagelayer.StorageLayer}.
     */
    public PublicEntityIdentifier(@NotNull PublicKey rsaEncryptionIdentifier,
                                  @NotNull PrivateKey rsaDecryptionIdentifier,
                                  @NotNull PublicParameters ibeIdentifier,
                                  @NotNull PublicParameters wibeIdentifier,
                                  @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        super(rsaEncryptionIdentifier, rsaDecryptionIdentifier, ibeIdentifier, wibeIdentifier);
        this.namespaceServiceProviderEmailAddressUserConcatenation = namespaceServiceProviderEmailAddressUserConcatenation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PublicEntityIdentifier that = (PublicEntityIdentifier) o;
        return namespaceServiceProviderEmailAddressUserConcatenation.equals(that.namespaceServiceProviderEmailAddressUserConcatenation);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), namespaceServiceProviderEmailAddressUserConcatenation);
    }
}
