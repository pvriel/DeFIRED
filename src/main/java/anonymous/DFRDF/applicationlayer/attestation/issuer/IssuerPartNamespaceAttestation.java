package anonymous.DFRDF.applicationlayer.attestation.issuer;

import anonymous.DFRDF.applicationlayer.attestation.NamespaceAttestation;
import anonymous.DFRDF.applicationlayer.attestation.policy.RTreePolicy;
import anonymous.DFRDF.encryptionlayer.entities.PrivateEntityIdentifier;
import anonymous.DFRDF.encryptionlayer.entities.PublicEntityIdentifier;
import anonymous.DFRDF.encryptionlayer.schemes.RSACipherEncryptedSegment;
import org.jetbrains.annotations.NotNull;
import anonymous.DFRDF.applicationlayer.revocation.RevocationCommitment;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.Objects;

/**
 * Class representing an {@link IssuerPartAttestation} for the {@link NamespaceAttestation}
 * instances.
 */
public class IssuerPartNamespaceAttestation extends IssuerPartAttestation {

    private final InetSocketAddress referenceAPILayer;

    /**
     * The constructor of the {@link IssuerPartNamespaceAttestation}.
     *
     * @param privateEntityIdentifierIssuer                The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierIssuer                 The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierReceiver               The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param revocationCommitment                         The {@link RevocationCommitment} of the issuer for the attestation.
     * @param rTreePolicy                                  The {@link RTreePolicy} for this attestation.
     * @param empiricalRSAKeyPair                           The empirical RSA {@link KeyPair} for this attestation.
     * @param referenceAPILayer                             The reference to the API layer for this attestation.
     * @throws IllegalArgumentException If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartNamespaceAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                          @NotNull RevocationCommitment revocationCommitment,
                                          @NotNull RTreePolicy rTreePolicy,
                                          @NotNull KeyPair empiricalRSAKeyPair,
                                          @NotNull InetSocketAddress referenceAPILayer) throws IllegalArgumentException {
        super(privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, publicEntityIdentifierReceiver,
                revocationCommitment, rTreePolicy, empiricalRSAKeyPair);
        this.referenceAPILayer = referenceAPILayer;
        updateSignature(empiricalRSAKeyPair.getPublic());
    }

    /**
     * The constructor of the {@link IssuerPartNamespaceAttestation}.
     *
     * @param privateEntityIdentifierIssuer                The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierIssuer                 The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierReceiver               The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param revocationCommitment                         The {@link RevocationCommitment} of the issuer for the attestation.
     * @param rTreePolicy                                  The {@link RTreePolicy} for this attestation.
     * @param referenceAPILayer                             The reference to the API layer for this attestation.
     * @throws IllegalArgumentException If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartNamespaceAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                          @NotNull RevocationCommitment revocationCommitment,
                                          @NotNull RTreePolicy rTreePolicy,
                                          @NotNull InetSocketAddress referenceAPILayer) throws IllegalArgumentException {
        this(privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, publicEntityIdentifierReceiver, revocationCommitment, rTreePolicy,
                RSACipherEncryptedSegment.generateKeyPair(), referenceAPILayer);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        IssuerPartNamespaceAttestation that = (IssuerPartNamespaceAttestation) o;
        return referenceAPILayer.equals(that.referenceAPILayer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), referenceAPILayer);
    }
}
