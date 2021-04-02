package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;

/**
 * Class representing a private {@link EntityIdentifier}.
 */
public class PrivateEntityIdentifier
        extends EntityIdentifier<PrivateKey, Pair<PublicParameters, BigInteger>, Pair<PublicParameters, BigInteger>> {

    /**
     * Constructor for the {@link PrivateEntityIdentifier} class.
     * @param   rsaIdentifier
     *          The {@link Key} used to represent the RSA part of the identifier.
     * @param   ibeIdentifier
     *          The IBE part of the identifier.
     * @param   wibeIdentifier
     *          The WIBE part of the identifier.
     */
    public PrivateEntityIdentifier(@NotNull PrivateKey rsaIdentifier, @NotNull Pair<PublicParameters, BigInteger> ibeIdentifier,
                                   @NotNull Pair<PublicParameters, BigInteger> wibeIdentifier) {
        super(rsaIdentifier, ibeIdentifier, wibeIdentifier);
    }
}
