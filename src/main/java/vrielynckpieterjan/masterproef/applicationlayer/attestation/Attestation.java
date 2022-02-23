package vrielynckpieterjan.masterproef.applicationlayer.attestation;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.ECCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.storagelayer.StorageElement;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing an attestation.
 */
public class Attestation extends StorageElement {

    private final IssuerPartAttestation firstLayer;
    private final ECCipherEncryptedSegment<Pair<Integer, RevocationCommitment>> secondLayer;
    private final ECCipherEncryptedSegment<Pair<Integer, StorageElementIdentifier>> thirdLayer;

    /**
     * Constructor for the {@link Attestation} class.
     * @param   identifier
     *          The {@link StorageElementIdentifier} which will be used / is used to store this
     *          {@link Attestation} with in the {@link StorageLayer} of the framework.
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
        secondLayer = new ECCipherEncryptedSegment<>(new ImmutablePair<>(
                signatureFirstLayer, revocationCommitmentReceiver), privateEntityIdentifierReceiver);
        thirdLayer = new ECCipherEncryptedSegment<>(new ImmutablePair<>(
                signatureFirstLayer, storageElementIdentifierNextQueueElement), privateEntityIdentifierReceiver);
    }

    /**
     * Method to check the validity of the {@link Attestation}.
     * @param   privateEntityIdentifierReceiver
     *          The {@link PrivateEntityIdentifier} of the user receiving the {@link Attestation}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @param   publicEntityIdentifierIssuer
     *          The {@link PublicEntityIdentifier} of the user issuing the {@link Attestation}.
     * @param   policy
     *          The {@link RTreePolicy} for the {@link Attestation}.
     * @return  True if the {@link Attestation} is valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity can't be checked with the provided encryption keys.
     */
    public boolean isValid(@NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver,
                           @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                           @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                           @NotNull RTreePolicy policy) throws IllegalArgumentException {
        if (!firstLayer.hasValidSignature(privateEntityIdentifierReceiver, publicEntityIdentifierIssuer, policy)) return false;
        return areSecondAndThirdLayerValid(publicEntityIdentifierReceiver);
    }

    /**
     * Method to check the validity of the {@link Attestation}.
     * @param   empiricalPrivateECKey
     *          The empirical EC {@link PrivateKey} of the {@link Attestation}.
     * @param   empiricalPublicECKey
     *          The empirical EC {@link PublicKey} of the {@link Attestation}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @return  True if the {@link Attestation} is valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity can't be checked with the provided encryption keys.
     */
    public boolean isValid(@NotNull PrivateKey empiricalPrivateECKey, @NotNull PublicKey empiricalPublicECKey,
                           @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver) throws IllegalArgumentException {
        if (!firstLayer.hasValidSignature(empiricalPrivateECKey, empiricalPublicECKey)) return false;
        return areSecondAndThirdLayerValid(publicEntityIdentifierReceiver);
    }

    /**
     * Method to return the {@link RTreePolicy} of this {@link Attestation}, if the {@link Attestation} is valid.
     * @param   firstAESKey
     *          The AES key to decrypt the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation} with.
     * @return  The {@link RTreePolicy} of this {@link Attestation}.
     * @throws  IllegalArgumentException
     *          If the provided AES key is incorrect, or if this {@link Attestation} is invalid.
     */
    public @NotNull RTreePolicy validateAndReturnPolicy(@NotNull String firstAESKey) throws IllegalArgumentException {
        var verificationInformationSegment = getFirstLayer().getVerificationInformationSegment().decrypt(firstAESKey);

        var empiricalPrivateECKey = verificationInformationSegment.getEncryptedEmpiricalPrivateECKey()
                .decrypt(verificationInformationSegment.getPublicEntityIdentifierIssuer());
        var empiricalPublicECKey = getFirstLayer().getEmpiricalPublicKey();
        var publicEntityIdentifierReceiver = getFirstLayer().getPublicEntityIdentifierReceiver();
        if (!isValid(empiricalPrivateECKey, empiricalPublicECKey, publicEntityIdentifierReceiver))
            throw new IllegalArgumentException("Attestation is not valid.");

        return verificationInformationSegment.getRTreePolicy();
    }

    /**
     * Method to check if this {@link Attestation} is revoked.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult.
     * @return  True if this {@link Attestation} is revoked; false otherwise.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     * @throws  IllegalArgumentException
     *          If the {@link Attestation} is invalid; that is, the {@link PublicEntityIdentifier}
     *          specified in the first layer for the receiver could not be used to decrypt the content
     *          of the second layer, which contains the second {@link RevocationCommitment}.
     */
    public boolean isRevoked(@NotNull StorageLayer storageLayer) throws IOException, IllegalArgumentException {
        var revocationCommitmentOne = getFirstLayer().getRevocationCommitment();
        var revocationCommitmentTwo = getSecondLayer().decrypt(
                getFirstLayer().getPublicEntityIdentifierReceiver()).getRight();
        for (RevocationCommitment revocationCommitment : new RevocationCommitment[]{revocationCommitmentOne, revocationCommitmentTwo}) {
            if (revocationCommitment.isRevealedInStorageLayer(storageLayer)) return true;
        }
        return false;
    }

    /**
     * Method to check if the second and third layers of the {@link Attestation} instance are valid.
     * @param   publicEntityIdentifierReceiver
     *          the {@link PublicEntityIdentifier} of the user receiving the {@link Attestation}.
     * @return  True if the layers are valid; false otherwise.
     * @throws  IllegalArgumentException
     *          If the validity of the layers can't be checked with the provided argument.
     */
    public boolean areSecondAndThirdLayerValid(@NotNull PublicEntityIdentifier publicEntityIdentifierReceiver)
        throws IllegalArgumentException {
        int signatureFirstLayer = firstLayer.hashCode();
        if (!secondLayer.decrypt(publicEntityIdentifierReceiver).getLeft().equals(signatureFirstLayer)) return false;
        return thirdLayer.decrypt(publicEntityIdentifierReceiver).getLeft().equals(signatureFirstLayer);
    }

    /**
     * Getter for the second layer.
     * @return  The second layer.
     */
    public ECCipherEncryptedSegment<Pair<Integer, RevocationCommitment>> getSecondLayer() {
        return secondLayer;
    }

    /**
     * Getter for the first layer.
     * @return  The first layer.
     */
    public IssuerPartAttestation getFirstLayer() {
        return firstLayer;
    }

    /**
     * Getter for the third layer.
     * @return  The third layer.
     */
    public ECCipherEncryptedSegment<Pair<Integer, StorageElementIdentifier>> getThirdLayer() {
        return thirdLayer;
    }
}
