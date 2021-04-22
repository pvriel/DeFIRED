package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.RSACipherEncryptedSegment;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Class representing the issuer's part of an {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation}.
 */
public class IssuerPartAttestation implements Serializable {

    private final PublicEntityIdentifier publicEntityIdentifierReceiver;
    private final RevocationCommitment revocationCommitment;
    private final PublicKey empiricalPublicKey;
    private RSACipherEncryptedSegment<Integer> encryptedSignature;

    private final AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> verificationInformationSegment;

    private final AESCipherEncryptedSegment<ProofInformationSegmentAttestation> proofInformationSegment;

    private final IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> aesEncryptionInformationSegment;

    /**
     * The constructor of the {@link IssuerPartAttestation}.
     * @param   privateEntityIdentifierIssuer
     *          The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierIssuer
     *          The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param   revocationCommitment
     *          The {@link RevocationCommitment} of the issuer for the attestation.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} for this attestation.
     * @param   empiricalRSAKeyPair
     *          The empirical RSA {@link KeyPair} for this attestation.
     * @throws  IllegalArgumentException
     *          If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                 @NotNull RevocationCommitment revocationCommitment,
                                 @NotNull RTreePolicy rTreePolicy,
                                 @NotNull KeyPair empiricalRSAKeyPair)
        throws IllegalArgumentException {
        // First, generate the necessary encryption keys.
        Pair<String, String> aesKeys = new ImmutablePair<>(AESCipherEncryptedSegment.generateAESKey(), AESCipherEncryptedSegment.generateAESKey());

        // Generate the plaintext header, except for the signature.
        this.publicEntityIdentifierReceiver = publicEntityIdentifierReceiver;
        this.revocationCommitment = revocationCommitment;
        empiricalPublicKey = empiricalRSAKeyPair.getPublic();

        // Multi-threading optimization preparation.
        var atomicReferenceVerificationInformationSegment = new AtomicReference<AESCipherEncryptedSegment<VerificationInformationSegmentAttestation>>();
        var atomicReferenceProofInformationSegment = new AtomicReference<AESCipherEncryptedSegment<ProofInformationSegmentAttestation>>();
        var atomicReferenceAESEncryptionInformationSegment = new AtomicReference<IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation>>();

        // Generate the verification information segment.
        new Thread(() -> atomicReferenceVerificationInformationSegment.set(new VerificationInformationSegmentAttestation(empiricalRSAKeyPair.getPrivate(),
                privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, rTreePolicy).encrypt(aesKeys.getLeft()))).start();


        // Generate the proof information segment.
        new Thread(() -> atomicReferenceProofInformationSegment.set(new ProofInformationSegmentAttestation(privateEntityIdentifierIssuer)
                .encrypt(aesKeys.getRight()))).start();

        // Generate the AES encryption information segment.
        new Thread(() -> atomicReferenceAESEncryptionInformationSegment.set(new AESEncryptionInformationSegmentAttestation(rTreePolicy, aesKeys,
                publicEntityIdentifierReceiver).encrypt(publicEntityIdentifierReceiver, rTreePolicy)));

        // Multi-threading optimization finalization.
        while (atomicReferenceVerificationInformationSegment.get() == null ||
                atomicReferenceProofInformationSegment.get() == null || atomicReferenceAESEncryptionInformationSegment == null) {}
        verificationInformationSegment = atomicReferenceVerificationInformationSegment.get();
        proofInformationSegment = atomicReferenceProofInformationSegment.get();
        aesEncryptionInformationSegment = atomicReferenceAESEncryptionInformationSegment.get();

        // Generate the signature for the plaintext header at the end.
        if (!(this instanceof IssuerPartNamespaceAttestation)) updateSignature(empiricalRSAKeyPair.getPublic());
    }

    /**
     * The constructor of the {@link IssuerPartAttestation}.
     * @param   privateEntityIdentifierIssuer
     *          The {@link PrivateEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierIssuer
     *          The {@link PublicEntityIdentifier} of the issuer of this {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the receiver of this {@link IssuerPartAttestation}.
     * @param   revocationCommitment
     *          The {@link RevocationCommitment} of the issuer for the attestation.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} for this attestation.
     * @throws  IllegalArgumentException
     *          If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                 @NotNull RevocationCommitment revocationCommitment,
                                 @NotNull RTreePolicy rTreePolicy)
            throws IllegalArgumentException {
        this(privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, publicEntityIdentifierReceiver,
                revocationCommitment, rTreePolicy,
                RSACipherEncryptedSegment.generateKeyPair());
    }

    /**
     * Getter for the encrypted version of the {@link AESEncryptionInformationSegmentAttestation}.
     * @return  The encrypted version of the {@link AESEncryptionInformationSegmentAttestation}.
     */
    public IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> getAesEncryptionInformationSegment() {
        return aesEncryptionInformationSegment;
    }

    /**
     * Method to update the signature of the {@link IssuerPartAttestation}.
     * @param   empiricalPublicRSAKey
     *          The empirical RSA {@link PublicKey} to encrypt the signature with.
     */
    protected void updateSignature(@NotNull PublicKey empiricalPublicRSAKey) {
        Integer fullHash = hashCode();
        encryptedSignature = new RSACipherEncryptedSegment<>(fullHash, empiricalPublicRSAKey);
    }

    /**
     * Method to check if the {@link IssuerPartAttestation} has a valid signature.
     * @param   empiricalPrivateRSAKey
     *          The empirical private RSA key of the attestation.
     * @param   empiricalPublicRSAKey
     *          The empirical public RSA key of the attestation.
     * @return  True if the {@link IssuerPartAttestation} has a valid signature; false otherwise.
     * @throws  IllegalArgumentException
     *          If the provided {@link java.security.Key} arguments can't be used to verify the signature.
     */
    public boolean hasValidSignature(@NotNull PrivateKey empiricalPrivateRSAKey, @NotNull PublicKey empiricalPublicRSAKey)
        throws IllegalArgumentException {
        // 1) Check if the two provided Keys actually form a pair.
        if (!RSACipherEncryptedSegment.keysPartOfKeypair(empiricalPrivateRSAKey, empiricalPublicRSAKey)) return false;

        // 2) Check if the signature is valid.
        Integer calculatedUnencryptedVersionSignature = hashCode();
        Integer decryptedSignature = encryptedSignature.decrypt(empiricalPrivateRSAKey);
        return calculatedUnencryptedVersionSignature.equals(decryptedSignature);
    }

    /**
     * Method to check if the {@link IssuerPartAttestation} has a valid signature.
     * @param   privateEntityIdentifierReceiver
     *          The {@link PrivateEntityIdentifier} of the user receiving the {@link IssuerPartAttestation}.
     * @param   publicEntityIdentifierIssuer
     *          The {@link PublicEntityIdentifier} of the issuer used to encrypt the AES encryption information segment with.
     * @param   policy
     *          The {@link RTreePolicy} for the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation}.
     * @return  True if the {@link IssuerPartAttestation} has a valid signature; false otherwise.
     * @throws  IllegalArgumentException
     *          If the provided arguments can't be used to verify the signature.
     */
    public boolean hasValidSignature(@NotNull PrivateEntityIdentifier privateEntityIdentifierReceiver,
                                     @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                     @NotNull RTreePolicy policy) throws IllegalArgumentException {
        // 1) Decrypt the AES encryption information segment.
        AESEncryptionInformationSegmentAttestation aesEncryptionInformationSegmentAttestation =
                aesEncryptionInformationSegment.decrypt(privateEntityIdentifierReceiver, policy.toString());

        // 2) Obtain the AES key information segment.
        Pair<String, String> aesKeyInformationSegment = aesEncryptionInformationSegmentAttestation.getAesKeyInformation();

        // 3) Decrypt the verification information segment using the first AES key.
        String aesKey = aesKeyInformationSegment.getLeft();
        VerificationInformationSegmentAttestation verificationInformationSegmentAttestation =
                verificationInformationSegment.decrypt(aesKey);

        // 4) Decrypt the encrypted version of the ephemeral public RSA key.
        PrivateKey empiricalPrivateRSAKey = verificationInformationSegmentAttestation.getEncryptedEmpiricalPrivateRSAKey()
                .decrypt(publicEntityIdentifierIssuer);

        // 5) The actual verification part.
        return hasValidSignature(empiricalPrivateRSAKey, empiricalPublicKey);
    }

    /**
     * Getter for the encrypted verification information segment.
     * @return  The encrypted verification information segment.
     */
    public AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> getVerificationInformationSegment() {
        return verificationInformationSegment;
    }

    /**
     * Getter for the empirical RSA {@link PublicKey}.
     * @return  The {@link PublicKey}.
     */
    public PublicKey getEmpiricalPublicKey() {
        return empiricalPublicKey;
    }

    /**
     * Getter for the {@link PublicEntityIdentifier} of the receiver of the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation}.
     * @return  The {@link PublicEntityIdentifier}.
     */
    public PublicEntityIdentifier getPublicEntityIdentifierReceiver() {
        return publicEntityIdentifierReceiver;
    }

    /**
     * Getter for the {@link RevocationCommitment} of the issuer of the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation}.
     * @return  The {@link RevocationCommitment}.
     */
    public RevocationCommitment getRevocationCommitment() {
        return revocationCommitment;
    }

    /**
     * Getter for the encrypted version of the {@link ProofInformationSegmentAttestation}.
     * @return  The encrypted object.
     */
    public AESCipherEncryptedSegment<ProofInformationSegmentAttestation> getProofInformationSegment() {
        return proofInformationSegment;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerPartAttestation that = (IssuerPartAttestation) o;
        return publicEntityIdentifierReceiver.equals(that.publicEntityIdentifierReceiver) && revocationCommitment.equals(that.revocationCommitment) && empiricalPublicKey.equals(that.empiricalPublicKey) && encryptedSignature.equals(that.encryptedSignature) && verificationInformationSegment.equals(that.verificationInformationSegment) && proofInformationSegment.equals(that.proofInformationSegment) && aesEncryptionInformationSegment.equals(that.aesEncryptionInformationSegment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicEntityIdentifierReceiver, revocationCommitment, empiricalPublicKey,
                verificationInformationSegment, proofInformationSegment, aesEncryptionInformationSegment);
    }

    @Override
    public String toString() {
        return "IssuerPartAttestation{" +
                "encryptedSignature=" + encryptedSignature +
                '}';
    }
}
