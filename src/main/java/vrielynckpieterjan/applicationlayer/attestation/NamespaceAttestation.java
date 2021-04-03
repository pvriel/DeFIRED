package vrielynckpieterjan.applicationlayer.attestation;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;

/**
 * Class representing a namespace {@link Attestation}.
 */
public class NamespaceAttestation extends Attestation {

    /**
     * Constructor for the {@link NamespaceAttestation} class.
     * @param   identifier
     *          The {@link StorageElementIdentifier} which will be used / is used to store this
     *          {@link Attestation} with in the {@link vrielynckpieterjan.storagelayer.StorageLayer} of the framework.
     * @param   firstLayer
     *          The issuer's generated part of the {@link Attestation}.
     * @param   revocationCommitmentReceiver
     *          The {@link RevocationCommitment} of the receiver of the {@link Attestation}.
     * @param   storageElementIdentifierNextQueueElement
     *          The {@link StorageElementIdentifier} for the next element in the receiver's personal queue.
     * @param   privateEntityIdentifierReceiver
     *          The {@link PrivateEntityIdentifier} of the receiver of the {@link Attestation}.
     * @throws  IllegalArgumentException
     *          If the provided encryption keys are invalid.
     */
    public NamespaceAttestation(@NotNull StorageElementIdentifier identifier,
                                @NotNull IssuerPartNamespaceAttestation firstLayer,
                                @NotNull RevocationCommitment revocationCommitmentReceiver,
                                @NotNull StorageElementIdentifier storageElementIdentifierNextQueueElement,
                                @NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver)
        throws IllegalArgumentException {
        super(identifier, firstLayer, revocationCommitmentReceiver, storageElementIdentifierNextQueueElement, privateEntityIdentifierReceiver);
    }
}
