package vrielynckpieterjan.applicationlayer.attestation;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.schemes.RSACipherEncryptedSegment;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing an attestation.
 */
public class Attestation extends StorageElement {

    private final IssuerPartAttestation firstLayer;
    private final RSACipherEncryptedSegment<Pair<Integer, RevocationCommitment>> secondLayer;
    private final RSACipherEncryptedSegment<Pair<Integer, StorageElementIdentifier>> thirdLayer;

    /**
     * Constructor for the {@link Attestation} class.
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
    public Attestation(@NotNull StorageElementIdentifier identifier,
                       @NotNull IssuerPartAttestation firstLayer,
                       @NotNull RevocationCommitment revocationCommitmentReceiver,
                       @NotNull StorageElementIdentifier storageElementIdentifierNextQueueElement,
                       @NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver) throws IllegalArgumentException {
        super(identifier);
        this.firstLayer = firstLayer;

        int signatureFirstLayer = firstLayer.hashCode();
        secondLayer = new RSACipherEncryptedSegment<>(new ImmutablePair<>(
                signatureFirstLayer, revocationCommitmentReceiver), privateEntityIdentifierReceiver);
        thirdLayer = new RSACipherEncryptedSegment<>(new ImmutablePair<>(
                signatureFirstLayer, storageElementIdentifierNextQueueElement), privateEntityIdentifierReceiver);
    }

    /**
     * Method to check the validity of the {@link Attestation}.
     * @param   privateEntityIdentifierReceiver
     *          The {@link PrivateEntityIdentifier} of the user receiving the {@link Attestation}.
     * @param   ibeIdentifier
     *          The IBE identifier used to encrypt the AES encryption information segment with.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @return  True if the {@link Attestation} is valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity can't be checked with the provided encryption keys.
     */
    public boolean isValid(@NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver,
                           @NotNull String ibeIdentifier,
                           @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver) throws IllegalArgumentException {
        if (!firstLayer.hasValidSignature(privateEntityIdentifierReceiver, ibeIdentifier)) return false;
        return areSecondAndThirdLayerValid(publicEntityIdentifierReceiver);
    }

    /**
     * Method to check the validity of the {@link Attestation}.
     * @param   empiricalPrivateRSAKey
     *          The empirical RSA {@link PrivateKey} of the {@link Attestation}.
     * @param   empiricalPublicRSAKey
     *          The empirical RSA {@link PublicKey} of the {@link Attestation}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @return  True if the {@link Attestation} is valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity can't be checked with the provided encryption keys.
     */
    public boolean isValid(@NotNull PrivateKey empiricalPrivateRSAKey, @NotNull PublicKey empiricalPublicRSAKey,
                           @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver) throws IllegalArgumentException {
        if (!firstLayer.hasValidSignature(empiricalPrivateRSAKey, empiricalPublicRSAKey)) return false;
        return areSecondAndThirdLayerValid(publicEntityIdentifierReceiver);
    }

    /**
     * Method to check if the second and third layers of the {@link Attestation} instance are valid.
     * @param   publicEntityIdentifierReceiver
     *          the {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @return  True if the layers are valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity of the layers can't be checked with the provided argument.
     */
    private boolean areSecondAndThirdLayerValid(@NotNull PublicEntityIdentifier publicEntityIdentifierReceiver)
        throws IllegalArgumentException {
        int signatureFirstLayer = firstLayer.hashCode();
        if (!secondLayer.decrypt(publicEntityIdentifierReceiver).getLeft().equals(signatureFirstLayer)) return false;
        return thirdLayer.decrypt(publicEntityIdentifierReceiver).getLeft().equals(signatureFirstLayer);
    }

    /**
     * Getter for the first layer.
     * @return  The first layer.
     */
    public IssuerPartAttestation getFirstLayer() {
        return firstLayer;
    }
}
