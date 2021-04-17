package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.jetbrains.annotations.NotNull;

import java.security.Key;
import java.security.PrivateKey;

/**
 * Class representing a public {@link EntityIdentifier}.
 */
public class PublicEntityIdentifier
        extends EntityIdentifier<PrivateKey, PublicParameters> {


    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     *
     * @param rsaIdentifier                               The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     *          This value should not be hashed yet.
     */
    protected PublicEntityIdentifier(@NotNull PrivateKey rsaIdentifier, @NotNull PublicParameters ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        super(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation);
    }
}
