package vrielynckpieterjan.applicationlayer.attestation.issuer;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.encryptionlayer.schemes.RSACipherEncryptedSegment;

import java.io.Serializable;
import java.security.PrivateKey;

/**
 * Class representing an non-encrypted version of the verification information segment
 * of the {@link IssuerPartAttestation}.
 * @implNote
 *          This class represents the non-encrypted version of the verification information segment.
 *          To obtain an encrypted version, call the encrypt(key) method.
 */
public class VerificationInformationSegmentAttestation implements Serializable {

    private final RSACipherEncryptedSegment<PrivateKey> encryptedEmpiricalPrivateRSAKey;
    private final PublicEntityIdentifier publicEntityIdentifierIssuer;
    private final RTreePolicy rTreePolicy;

    /**
     * Constructor for the {@link VerificationInformationSegmentAttestation} class.
     * @param   empiricalPrivateRSAKey
     *          The empirical RSA {@link PrivateKey} instance of the {@link IssuerPartAttestation}.
     * @param   privateEntityIdentifierIssuer
     *          The {@link PrivateEntityIdentifier} of the entity issuing the {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierIssuer
     *          The {@link PublicEntityIdentifier} of the entity issuing the {@link IssuerPartAttestation}.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} describing the policy of the {@link IssuerPartAttestation}.
     */
    public VerificationInformationSegmentAttestation(@NotNull PrivateKey empiricalPrivateRSAKey,
                                                     @NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                                     @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                                     @NotNull RTreePolicy rTreePolicy)
        throws IllegalArgumentException {
        encryptedEmpiricalPrivateRSAKey = new RSACipherEncryptedSegment<>(empiricalPrivateRSAKey, privateEntityIdentifierIssuer);
        this.publicEntityIdentifierIssuer = publicEntityIdentifierIssuer;
        this.rTreePolicy = rTreePolicy;
    }

    /**
     * Method to return an encrypted version of this {@link VerificationInformationSegmentAttestation} instance.
     * @param   aesKey
     *          The AES key to encrypt this instance with.
     * @return  The encrypted instance, as a {@link AESCipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key could not be used to encrypt this instance with.
     */
    public @NotNull AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> encrypt(@NotNull String aesKey)
        throws IllegalArgumentException {
        return new AESCipherEncryptedSegment<>(this, aesKey);
    }

    /**
     * Getter for the {@link PublicEntityIdentifier} of the issuer of the {@link IssuerPartAttestation}.
     * @return  The {@link PublicEntityIdentifier} of the issuer of the {@link IssuerPartAttestation}.
     */
    public PublicEntityIdentifier getPublicEntityIdentifierIssuer() {
        return publicEntityIdentifierIssuer;
    }

    /**
     * Getter for the {@link RSACipherEncryptedSegment} instance, representing an RSA encrypted version
     * of the empirical RSA {@link PrivateKey} instance for the {@link IssuerPartAttestation}.
     * @return  The {@link RSACipherEncryptedSegment}.
     */
    public RSACipherEncryptedSegment<PrivateKey> getEncryptedEmpiricalPrivateRSAKey() {
        return encryptedEmpiricalPrivateRSAKey;
    }

    /**
     * Getter for the {@link RTreePolicy} instance describing the policy of the {@link IssuerPartAttestation}.
     * @return  The {@link RTreePolicy}.
     */
    public RTreePolicy getRTreePolicy() {
        return rTreePolicy;
    }
}
