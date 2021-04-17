package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Class representing the proof information segment of the {@link IssuerPartAttestation}.
 */
public class ProofInformationSegmentAttestation implements Serializable {

    private final PublicParameters publicParametersIBE;
    private final BigInteger masterSecretIBE;

    /**
     * Constructor for the {@link ProofInformationSegmentAttestation} class.
     * @param   privateEntityIdentifierIssuer
     *          The {@link PrivateEntityIdentifier} of the user issuing the {@link IssuerPartAttestation}.
     */
    public ProofInformationSegmentAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer) {
        publicParametersIBE = privateEntityIdentifierIssuer.getIBEIdentifier().getLeft();
        masterSecretIBE = privateEntityIdentifierIssuer.getIBEIdentifier().getRight();
    }

    /**
     * Getter for the IBE PKG of the issuer of the {@link IssuerPartAttestation}.
     * @return  The IBE PKG.
     */
    public Pair<PublicParameters, BigInteger> getIBEPKG() {
        return new ImmutablePair<>(publicParametersIBE, masterSecretIBE);
    }

    /**
     * Method to encrypt this {@link ProofInformationSegmentAttestation} instance using AES encryption.
     * @param   aesKey
     *          The AES key to encrypt this instance with.
     * @return  The encrypted instance as a {@link AESCipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided AES key can't be used to encrypt this instance with.
     */
    public @NotNull AESCipherEncryptedSegment<ProofInformationSegmentAttestation> encrypt(@NotNull String aesKey)
        throws IllegalArgumentException {
        return new AESCipherEncryptedSegment<>(this, aesKey);
    }
}
