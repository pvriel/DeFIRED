package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.ECCipherEncryptedSegment;

import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.Objects;

/**
 * Class representing an {@link IssuerPartAttestation} for the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation}
 * instances.
 */
public class IssuerPartNamespaceAttestation extends IssuerPartAttestation {

    private final InetSocketAddress referenceAPILayer;

    /**
     * The constructor of the {@link IssuerPartNamespaceAttestation}.
     *
     * @param privateEntityIdentifierIssuer  The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierIssuer   The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierReceiver The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param revocationCommitment           The {@link RevocationCommitment} of the issuer for the attestation.
     * @param rTreePolicy                    The {@link RTreePolicy} for this attestation.
     * @param empiricalECKeyPair             The empirical EC {@link KeyPair} for this attestation.
     * @param referenceAPILayer              The reference to the API layer for this attestation.
     * @throws IllegalArgumentException If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartNamespaceAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                          @NotNull RevocationCommitment revocationCommitment,
                                          @NotNull RTreePolicy rTreePolicy,
                                          @NotNull KeyPair empiricalECKeyPair,
                                          @NotNull InetSocketAddress referenceAPILayer) throws IllegalArgumentException {
        super(privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, publicEntityIdentifierReceiver,
                revocationCommitment, rTreePolicy, empiricalECKeyPair);
        this.referenceAPILayer = referenceAPILayer;
        updateSignature(empiricalECKeyPair.getPublic());
    }

    /**
     * The constructor of the {@link IssuerPartNamespaceAttestation}.
     *
     * @param privateEntityIdentifierIssuer  The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierIssuer   The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param publicEntityIdentifierReceiver The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param revocationCommitment           The {@link RevocationCommitment} of the issuer for the attestation.
     * @param rTreePolicy                    The {@link RTreePolicy} for this attestation.
     * @param referenceAPILayer              The reference to the API layer for this attestation.
     * @throws IllegalArgumentException If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartNamespaceAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                          @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                          @NotNull RevocationCommitment revocationCommitment,
                                          @NotNull RTreePolicy rTreePolicy,
                                          @NotNull InetSocketAddress referenceAPILayer) throws IllegalArgumentException {
        this(privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, publicEntityIdentifierReceiver, revocationCommitment, rTreePolicy,
                ECCipherEncryptedSegment.generateKeyPair(), referenceAPILayer);
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
