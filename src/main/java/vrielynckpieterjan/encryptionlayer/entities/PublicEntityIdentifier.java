package vrielynckpieterjan.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.jetbrains.annotations.NotNull;

import java.security.Key;
import java.security.PublicKey;

/**
 * Class representing a public {@link EntityIdentifier}.
 */
public class PublicEntityIdentifier
        extends EntityIdentifier<PublicKey, PublicParameters, PublicParameters> {

    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     * @param   rsaIdentifier
     *          The {@link Key} used to represent the RSA part of the identifier.
     * @param   ibeIdentifier
     *          The IBE part of the identifier.
     * @param   wibeIdentifier
     *          The WIBE part of the identifier.
     */
    public PublicEntityIdentifier(@NotNull PublicKey rsaIdentifier, @NotNull PublicParameters ibeIdentifier,
                                  @NotNull PublicParameters wibeIdentifier) {
        super(rsaIdentifier, ibeIdentifier, wibeIdentifier);
    }
}
