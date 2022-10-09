package vrielynckpieterjan.masterproef.applicationlayer.attestation;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;

/**
 * Class representing a namespace {@link Attestation}.
 */
public class NamespaceAttestation extends Attestation {

    /**
     * Constructor for the {@link NamespaceAttestation} class.
     *
     * @param firstLayer                               The issuer's generated part of the {@link Attestation}.
     * @param revocationCommitmentReceiver             The {@link RevocationCommitment} of the receiver of the {@link Attestation}.
     * @param storageElementIdentifierNextQueueElement The {@link StorageElementIdentifier} for the next element in the receiver's personal queue.
     * @param publicEntityIdentifierReceiver           The {@link PublicEntityIdentifier} of the receiver of the {@link Attestation}.
     * @param privateEntityIdentifierReceiver          The {@link PrivateEntityIdentifier} of the receiver of the {@link Attestation}.
     * @throws IllegalArgumentException If the provided encryption keys are invalid.
     */
    public NamespaceAttestation(@NotNull IssuerPartNamespaceAttestation firstLayer,
                                @NotNull RevocationCommitment revocationCommitmentReceiver,
                                @NotNull StorageElementIdentifier storageElementIdentifierNextQueueElement,
                                @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                @NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver)
            throws IllegalArgumentException {
        super(new StorageElementIdentifier(publicEntityIdentifierReceiver.getNamespaceServiceProviderEmailAddressUserConcatenation()),
                firstLayer, revocationCommitmentReceiver, storageElementIdentifierNextQueueElement,
                privateEntityIdentifierReceiver);
    }
}
