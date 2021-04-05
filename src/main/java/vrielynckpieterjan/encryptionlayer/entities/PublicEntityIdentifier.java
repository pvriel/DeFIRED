package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.jetbrains.annotations.NotNull;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing a public {@link EntityIdentifier}.
 */
public class PublicEntityIdentifier
        extends EntityIdentifier<PublicKey, PrivateKey, PublicParameters, PublicParameters> {


    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     *
     * @param rsaEncryptionIdentifier                               The {@link Key} used to represent the first RSA part of the identifier.
     * @param rsaDecryptionIdentifier                               The {@link Key} used to represent the second RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param wibeIdentifier                                        The WIBE part of the identifier.
     * @param namespaceServiceProviderEmailAddressUserConcatenation
     */
    public PublicEntityIdentifier(@NotNull PublicKey rsaEncryptionIdentifier, @NotNull PrivateKey rsaDecryptionIdentifier, @NotNull PublicParameters ibeIdentifier, @NotNull PublicParameters wibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        super(rsaEncryptionIdentifier, rsaDecryptionIdentifier, ibeIdentifier, wibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation);
    }
}
