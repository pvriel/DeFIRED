package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing a private {@link EntityIdentifier}.
 */
public class PrivateEntityIdentifier
        extends EntityIdentifier<PrivateKey, PublicKey, Pair<PublicParameters, BigInteger>> {


    /**
     * Constructor for the {@link PrivateEntityIdentifier} class.
     *
     * @param rsaEncryptionIdentifier                               The {@link Key} used to represent the first RSA part of the identifier.
     * @param rsaDecryptionIdentifier                               The {@link Key} used to represent the second RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     *          This value should not be hashed yet.
     */
    protected PrivateEntityIdentifier(@NotNull PrivateKey rsaEncryptionIdentifier, @NotNull PublicKey rsaDecryptionIdentifier, @NotNull Pair<PublicParameters, BigInteger> ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        super(rsaEncryptionIdentifier, rsaDecryptionIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation);
    }
}
