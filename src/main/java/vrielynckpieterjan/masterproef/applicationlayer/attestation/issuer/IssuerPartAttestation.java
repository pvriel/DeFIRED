package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import cryptid.ibe.PrivateKeyGenerator;
import cryptid.ibe.domain.PublicParameters;
import cryptid.ibe.exception.ComponentConstructionException;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.ECCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Class representing the issuer's part of an {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation}.
 */
public class IssuerPartAttestation implements Exportable {

    private final PublicEntityIdentifier publicEntityIdentifierReceiver;
    private final RevocationCommitment revocationCommitment;
    private final PublicKey empiricalPublicKey;
    private ECCipherEncryptedSegment<Integer> encryptedSignature;

    private final AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> verificationInformationSegment;

    private final AESCipherEncryptedSegment<ProofInformationSegmentAttestation> proofInformationSegment;

    private final IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> aesEncryptionInformationSegment;


    public static void main(String[] args) throws IOException {
        var policy = new RTreePolicy(PolicyRight.READ, "A");
        var entityPair = EntityIdentifier.generateEntityIdentifierPair("test");
        var issuerPartAttestation = new IssuerPartAttestation(entityPair.getLeft(),
                entityPair.getRight(), entityPair.getRight(), new RevocationCommitment(), policy);
        var serialized = ExportableUtils.serialize(issuerPartAttestation);
        var deserialized = ExportableUtils.deserialize(serialized, IssuerPartAttestation.class);
        System.out.println(deserialized.equals(issuerPartAttestation));
    }

    protected IssuerPartAttestation(@NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                    @NotNull RevocationCommitment revocationCommitment,
                                    @NotNull PublicKey empiricalPublicKey,
                                    @NotNull ECCipherEncryptedSegment<Integer> encryptedSignature,
                                    @NotNull AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> verificationInformationSegment,
                                    @NotNull AESCipherEncryptedSegment<ProofInformationSegmentAttestation> proofInformationSegment,
                                    @NotNull IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> aesEncryptionInformationSegment) {
        this.publicEntityIdentifierReceiver = publicEntityIdentifierReceiver;
        this.revocationCommitment = revocationCommitment;
        this.empiricalPublicKey = empiricalPublicKey;
        this.encryptedSignature = encryptedSignature;
        this.verificationInformationSegment =verificationInformationSegment;
        this.proofInformationSegment = proofInformationSegment;
        this.aesEncryptionInformationSegment =aesEncryptionInformationSegment;
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
     * @param   empiricalECKeyPair
     *          The empirical EC {@link KeyPair} for this attestation.
     * @throws  IllegalArgumentException
     *          If an invalid key was provided for the encryption schemes used during the construction process.
     */
    public IssuerPartAttestation(@NotNull PrivateEntityIdentifier privateEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierIssuer,
                                 @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
                                 @NotNull RevocationCommitment revocationCommitment,
                                 @NotNull RTreePolicy rTreePolicy,
                                 @NotNull KeyPair empiricalECKeyPair)
        throws IllegalArgumentException {
        // First, generate the necessary encryption keys.
        Pair<String, String> aesKeys = new ImmutablePair<>(AESCipherEncryptedSegment.generateAESKey(), AESCipherEncryptedSegment.generateAESKey());

        // Generate the plaintext header, except for the signature.
        this.publicEntityIdentifierReceiver = publicEntityIdentifierReceiver;
        this.revocationCommitment = revocationCommitment;
        empiricalPublicKey = empiricalECKeyPair.getPublic();

        // Multi-threading optimization preparation.
        var atomicReferenceVerificationInformationSegment = new AtomicReference<AESCipherEncryptedSegment<VerificationInformationSegmentAttestation>>();
        var atomicReferenceProofInformationSegment = new AtomicReference<AESCipherEncryptedSegment<ProofInformationSegmentAttestation>>();
        var atomicReferenceAESEncryptionInformationSegment = new AtomicReference<IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation>>();
        var thrownException = new AtomicReference<IllegalArgumentException>();

        // Generate the verification information segment.
        var threadOne = new Thread(() -> atomicReferenceVerificationInformationSegment.set(new VerificationInformationSegmentAttestation(empiricalECKeyPair.getPrivate(),
                privateEntityIdentifierIssuer, publicEntityIdentifierIssuer, rTreePolicy).encrypt(aesKeys.getLeft())));


        // Generate the proof information segment.
        var threadTwo = new Thread(() -> {
            try {
                PrivateKeyGenerator pkgIssuer = IBEDecryptableSegment.obtainPKG(privateEntityIdentifierIssuer);
                List<RTreePolicy> policyList = rTreePolicy.generateRTreePolicyVariations();
                Set<cryptid.ibe.domain.PrivateKey> IBEKeys = new HashSet<>();
                for (RTreePolicy policy : policyList) {
                    IBEKeys.add(pkgIssuer.extract(policy.toString()));
                }
                atomicReferenceProofInformationSegment.set(new ProofInformationSegmentAttestation(IBEKeys)
                        .encrypt(aesKeys.getRight()));
            } catch (ComponentConstructionException e) {
                thrownException.set(new IllegalArgumentException(e));
            }
        });

        // Generate the AES encryption information segment.
        var threadThree = new Thread(() -> atomicReferenceAESEncryptionInformationSegment.set(new AESEncryptionInformationSegmentAttestation(rTreePolicy, aesKeys,
                publicEntityIdentifierReceiver).encrypt(publicEntityIdentifierReceiver, rTreePolicy)));

        // Multi-threading optimization finalization.
        threadOne.start();
        threadTwo.start();
        threadThree.start();
        try {
            threadOne.join();
            threadTwo.join();
            threadThree.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
            System.exit(1);
        }
        if (thrownException.get() != null) throw thrownException.get();

        verificationInformationSegment = atomicReferenceVerificationInformationSegment.get();
        proofInformationSegment = atomicReferenceProofInformationSegment.get();
        aesEncryptionInformationSegment = atomicReferenceAESEncryptionInformationSegment.get();

        // Generate the signature for the plaintext header at the end.
        if (!(this instanceof IssuerPartNamespaceAttestation)) updateSignature(empiricalECKeyPair.getPublic());
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
                ECCipherEncryptedSegment.generateKeyPair());
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
     * @param   empiricalPublicECKey
     *          The empirical EC {@link PublicKey} to encrypt the signature with.
     */
    protected void updateSignature(@NotNull PublicKey empiricalPublicECKey) {
        Integer fullHash = hashCode();
        encryptedSignature = new ECCipherEncryptedSegment<>(fullHash, empiricalPublicECKey);
    }

    /**
     * Method to check if the {@link IssuerPartAttestation} has a valid signature.
     * @param   empiricalPrivateECKey
     *          The empirical private EC key of the attestation.
     * @param   empiricalPublicECKey
     *          The empirical public EC key of the attestation.
     * @return  True if the {@link IssuerPartAttestation} has a valid signature; false otherwise.
     * @throws  IllegalArgumentException
     *          If the provided {@link java.security.Key} arguments can't be used to verify the signature.
     */
    public boolean hasValidSignature(@NotNull PrivateKey empiricalPrivateECKey, @NotNull PublicKey empiricalPublicECKey)
        throws IllegalArgumentException {
        // 1) Check if the two provided Keys actually form a pair.
        if (!ECCipherEncryptedSegment.keysPartOfKeypair(empiricalPrivateECKey, empiricalPublicECKey)) return false;

        // 2) Check if the signature is valid.
        Integer calculatedUnencryptedVersionSignature = hashCode();
        Integer decryptedSignature = encryptedSignature.decrypt(empiricalPrivateECKey);
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
                aesEncryptionInformationSegment.decrypt(privateEntityIdentifierReceiver, policy);

        // 2) Obtain the AES key information segment.
        Pair<String, String> aesKeyInformationSegment = aesEncryptionInformationSegmentAttestation.getAesKeyInformation();

        // 3) Decrypt the verification information segment using the first AES key.
        String aesKey = aesKeyInformationSegment.getLeft();
        VerificationInformationSegmentAttestation verificationInformationSegmentAttestation =
                verificationInformationSegment.decrypt(aesKey);

        // 4) Decrypt the encrypted version of the ephemeral public EC key.
        PrivateKey empiricalPrivateECKey = verificationInformationSegmentAttestation.getEncryptedEmpiricalPrivateECKey()
                .decrypt(publicEntityIdentifierIssuer);

        // 5) The actual verification part.
        return hasValidSignature(empiricalPrivateECKey, empiricalPublicKey);
    }

    /**
     * Getter for the encrypted verification information segment.
     * @return  The encrypted verification information segment.
     */
    public AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> getVerificationInformationSegment() {
        return verificationInformationSegment;
    }

    /**
     * Getter for the empirical EC {@link PublicKey}.
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

    @Override
    public byte[] serialize() throws IOException {
        byte[] publicEntityIdentifierReceiverAsByteArray = ExportableUtils.serialize(publicEntityIdentifierReceiver);
        byte[] revocationCommitmentAsByteArray = ExportableUtils.serialize(revocationCommitment);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(empiricalPublicKey);
        byte[] empiricalPublicKeyAsByteArray = byteArrayOutputStream.toByteArray();
        byte[] encryptedSignatureAsByteArray = ExportableUtils.serialize(encryptedSignature);
        byte[] verificationInformationSegmentAsByteArray = ExportableUtils.serialize(verificationInformationSegment);
        byte[] proofInformationSegmentAsByteArray = ExportableUtils.serialize(proofInformationSegment);
        byte[] aesEncryptionInformationSegmentAsByteArray = ExportableUtils.serialize(aesEncryptionInformationSegment);

        ByteBuffer byteBuffer = ByteBuffer.allocate(6 * 4 + publicEntityIdentifierReceiverAsByteArray.length +
                revocationCommitmentAsByteArray.length + empiricalPublicKeyAsByteArray.length + encryptedSignatureAsByteArray.length +
                verificationInformationSegmentAsByteArray.length + proofInformationSegmentAsByteArray.length + aesEncryptionInformationSegmentAsByteArray.length);
        for (byte[] array : new byte[][]{publicEntityIdentifierReceiverAsByteArray, revocationCommitmentAsByteArray,
                empiricalPublicKeyAsByteArray, encryptedSignatureAsByteArray, verificationInformationSegmentAsByteArray,
                proofInformationSegmentAsByteArray}) {
            byteBuffer.putInt(array.length);
            byteBuffer.put(array);
        }
        byteBuffer.put(aesEncryptionInformationSegmentAsByteArray);

        return byteBuffer.array();
    }

    @NotNull
    public static IssuerPartAttestation deserialize(@NotNull ByteBuffer byteBuffer) throws IOException, ClassNotFoundException {
        byte[][] receivedArrays = new byte[7][];
        for (int i = 0; i < receivedArrays.length - 1; i ++) {
            byte[] array = new byte[byteBuffer.getInt()];
            byteBuffer.get(array);
            receivedArrays[i] = array;
        }
        receivedArrays[6] = new byte[byteBuffer.remaining()];
        byteBuffer.get(receivedArrays[6]);

        PublicEntityIdentifier publicEntityIdentifierReceiver = ExportableUtils.deserialize(receivedArrays[0], PublicEntityIdentifier.class);
        RevocationCommitment revocationCommitment = ExportableUtils.deserialize(receivedArrays[1], RevocationCommitment.class);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(receivedArrays[2]);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        PublicKey empiricalPublicKey = (PublicKey) objectInputStream.readObject();
        ECCipherEncryptedSegment<Integer> encryptedSignature = ExportableUtils.deserialize(receivedArrays[3], ECCipherEncryptedSegment.class);
        AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> verificationInformationSegment =
                ExportableUtils.deserialize(receivedArrays[4], AESCipherEncryptedSegment.class);
        AESCipherEncryptedSegment<ProofInformationSegmentAttestation> proofInformationSegment =
                ExportableUtils.deserialize(receivedArrays[5], AESCipherEncryptedSegment.class);
        IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> aesEncryptionInformationSegment =
                ExportableUtils.deserialize(receivedArrays[6], IBEDecryptableSegment.class);

        return new IssuerPartAttestation(publicEntityIdentifierReceiver, revocationCommitment,
                empiricalPublicKey, encryptedSignature, verificationInformationSegment, proofInformationSegment, aesEncryptionInformationSegment);
    }
}
