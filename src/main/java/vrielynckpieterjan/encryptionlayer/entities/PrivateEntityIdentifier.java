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
        extends EntityIdentifier<PrivateKey, PublicKey, Pair<PublicParameters, BigInteger>, Pair<PublicParameters, BigInteger>> {


    /**
     * Constructor for the {@link EntityIdentifier} class.
     *
     * @param rsaEncryptionIdentifier The {@link Key} used to represent the first RSA part of the identifier.
     * @param rsaDecryptionIdentifier The {@link Key} used to represent the second RSA part of the identifier.
     * @param ibeIdentifier           The IBE part of the identifier.
     * @param wibeIdentifier            The WIBE part of the identifier.
     */
    public PrivateEntityIdentifier(@NotNull PrivateKey rsaEncryptionIdentifier, @NotNull PublicKey rsaDecryptionIdentifier,
                                   @NotNull Pair<PublicParameters, BigInteger> ibeIdentifier, @NotNull Pair<PublicParameters,
            BigInteger> wibeIdentifier) {
        super(rsaEncryptionIdentifier, rsaDecryptionIdentifier, ibeIdentifier, wibeIdentifier);
    }
}
