package vrielynckpieterjan.applicationlayer.proof;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.ProofInformationSegmentAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation;
import vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/**
 * Class representing a proof object.
 */
public class ProofObject implements Serializable {

    private final static Logger logger = Logger.getLogger(ProofObject.class.getName());

    private final StorageElementIdentifier[] storageElementIdentifiers;
    private final String[] aesKeys;
    private final String aesKeyNamespaceAttestationProver;

    /**
     * Constructor for the {@link ProofObject} class.
     * @param   storageElementIdentifiers
     *          The {@link StorageElementIdentifier}s for the {@link Attestation}s for the proof.
     * @param   aesKeys
     *          The AES keys for the {@link Attestation}s for the proof.
     * @param   aesKeyNamespaceAttestationProver
     *          The AES key for the {@link NamespaceAttestation} of the prover, for the proof.
     * @throws  IllegalArgumentException
     *          If one of the two provided arrays has length zero, the lengths don't match
     *          or one of the two arrays contains a null value.
     */
    public ProofObject(StorageElementIdentifier[] storageElementIdentifiers,
                       String[] aesKeys, @NotNull String aesKeyNamespaceAttestationProver) throws IllegalArgumentException {
        if (storageElementIdentifiers.length == 0) throw new IllegalArgumentException("Not enough StorageElementIdentifiers provided.");
        if (storageElementIdentifiers.length != aesKeys.length) throw new IllegalArgumentException(String.format("" +
                "An equal amount of StorageElementIdentifiers (total: %s) and AES keys (total: %s) should be provided.",
                storageElementIdentifiers.length, aesKeys.length));
        for (int i = 0; i< storageElementIdentifiers.length; i ++) {
            if (storageElementIdentifiers[i] == null) throw new IllegalArgumentException(String.format(
                    "The storageElementIdentifiers argument contains a null value at index %s.", i));
            if (aesKeys[i] == null) throw new IllegalArgumentException(String.format(
                    "The aesKeys argument contains a null value at index %s.", i));
        }

        this.storageElementIdentifiers = storageElementIdentifiers;
        this.aesKeys = aesKeys;
        this.aesKeyNamespaceAttestationProver = aesKeyNamespaceAttestationProver;
    }

    /**
     * Method to verify the {@link ProofObject} and return the proven {@link RTreePolicy}.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult during the verification process.
     * @return  The proven {@link RTreePolicy}.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     * @throws  IllegalArgumentException
     *          If the {@link ProofObject} could not be verified.
     */
    public @NotNull RTreePolicy verify(@NotNull StorageLayer storageLayer) throws IOException, IllegalArgumentException {
        logger.info(String.format("Trying to verify ProofObject (%s)...", this));

        RTreePolicy currentPolicy = null;
        PublicEntityIdentifier publicEntityIdentifierProver = null;
        for (int i = 0; i < storageElementIdentifiers.length; i ++) {
            logger.info(String.format("Verifying the %sth Attestation with StorageElementIdentifier (%s)" +
                    " for ProofObject (%s)...", i, storageElementIdentifiers[i], this));
            var currentPairAttestation = searchAndExtractRTreePolicyFromAttestation(
                    storageElementIdentifiers[i], aesKeys[i], storageLayer);

            var retrievedAttestation = currentPairAttestation.getLeft();
            if (i == 0 && !(retrievedAttestation instanceof NamespaceAttestation)) throw new IllegalArgumentException(
                    "ProofObject does not start with a NamespaceAttestation.");
            if (i == storageElementIdentifiers.length - 1) publicEntityIdentifierProver = retrievedAttestation.getFirstLayer().getPublicEntityIdentifierReceiver();

            var retrievedPolicy = currentPairAttestation.getRight();
            currentPolicy = mergePoliciesForVerificationProcess(currentPolicy, retrievedPolicy);
        }

        logger.info(String.format("Verifying the NamespaceAttestation of the prover with PublicEntityIdentifier (%s)" +
                " for ProofObject (%s)...", publicEntityIdentifierProver, this));
        var namespaceAttestationPairProver = searchAndExtractRTreePolicyFromAttestation(new StorageElementIdentifier(publicEntityIdentifierProver.getNamespaceServiceProviderEmailAddressUserConcatenation()),
                aesKeyNamespaceAttestationProver, storageLayer);
        if (!(namespaceAttestationPairProver.getLeft() instanceof NamespaceAttestation))
            throw new IllegalArgumentException(String.format("Could not verify the NamespaceAttestation of the prover" +
                    " with PublicEntityIdentifier (%s).", publicEntityIdentifierProver));

        logger.info(String.format("ProofObject (%s) verified.", this));
        return currentPolicy;
    }

    /**
     * Method to merge two {@link RTreePolicy}s for the verification process.
     * @param   currentlyHoldingPolicy
     *          The currently evaluated {@link RTreePolicy}, e.g. READ://A/B.
     * @param   retrievedPolicy
     *          The new {@link RTreePolicy}, e.g. WRITE://A/B/C.
     * @return  The retrievedPolicy argument, of which the {@link PolicyRight} is adjusted so that it's
     *          equal to the most strict {@link PolicyRight} arguments. To continue the example given in this
     *          documentation, the return value would be READ://A/B/C.
     * @throws  IllegalArgumentException
     *          If the two {@link RTreePolicy}s can't be merge in any way.
     */
    private static @NotNull RTreePolicy mergePoliciesForVerificationProcess(
            RTreePolicy currentlyHoldingPolicy,
            @NotNull RTreePolicy retrievedPolicy) throws IllegalArgumentException {
        if (currentlyHoldingPolicy == null || currentlyHoldingPolicy.coversRTreePolicy(retrievedPolicy)) return retrievedPolicy;
        /*
        It's possible that the currentlyHoldingPolicy argument allows READ access, while the
        retrievedPolicy allows WRITE access.
        Make a copy of the retrievedPolicy RTreePolicy, convert it to READ access and try again.
         */
        if (currentlyHoldingPolicy.getPolicyRight().equals(PolicyRight.READ) && retrievedPolicy.getPolicyRight().equals(PolicyRight.WRITE)) {
            var clonedRetrievedPolicy = retrievedPolicy.clone();
            clonedRetrievedPolicy.setPolicyRight(PolicyRight.READ);
            if (currentlyHoldingPolicy.coversRTreePolicy(clonedRetrievedPolicy)) return clonedRetrievedPolicy;
        }
        throw new IllegalArgumentException(String.format("The currently holding RTreePolicy (%s)" +
                " can't cover the retrieved RTreePolicy (%s) in any way.", currentlyHoldingPolicy, retrievedPolicy));
    }

    /**
     * Method to search an {@link Attestation} in the {@link StorageLayer} for the given
     * {@link StorageElementIdentifier}, from which the unencrypted {@link vrielynckpieterjan.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation}
     * can be extracted using the provided AES key.
     * The latter part is done to extract the {@link RTreePolicy} from the {@link Attestation} instance.
     * @param   storageElementIdentifier
     *          The {@link StorageElementIdentifier} to find the {@link Attestation} with.
     * @param   firstAESKeyAttestation
     *          The AES key to decrypt the encrypted version of the {@link vrielynckpieterjan.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation} of
     *          the {@link Attestation} with.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult.
     * @return  The found {@link Attestation} and its extracted
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     * @throws  IllegalArgumentException
     *          If the provided AES key is invalid.
     */
    private @NotNull Pair<Attestation, RTreePolicy> searchAndExtractRTreePolicyFromAttestation (
            @NotNull StorageElementIdentifier storageElementIdentifier,
            @NotNull String firstAESKeyAttestation,
            @NotNull StorageLayer storageLayer) throws IOException, IllegalArgumentException {
        Set<Attestation> retrievedAttestations = storageLayer.retrieve(storageElementIdentifier, Attestation.class);
        Set<NamespaceAttestation> retrievedNamespaceAttestations = storageLayer.retrieve(storageElementIdentifier, NamespaceAttestation.class);
        retrievedAttestations.addAll(retrievedNamespaceAttestations);
        if (retrievedAttestations.size() == 0) throw new IllegalArgumentException(String.format(
                "No Attestations found for the StorageElementIdentifier (%s).", storageElementIdentifier));

        for (Attestation retrievedAttestation : retrievedAttestations) {
            if (retrievedAttestation.isRevoked(storageLayer)) continue;
            try {
                return new ImmutablePair<>(retrievedAttestation, retrievedAttestation.validateAndReturnPolicy(firstAESKeyAttestation));
            } catch (IllegalArgumentException ignored) {}
        }

        throw new IllegalArgumentException(String.format("No Attestations found for the StorageElementIdentifier (%s)" +
                " which could be decrypted using the provided AES key (%s).", storageElementIdentifier, firstAESKeyAttestation));
    }

    @Override
    public String toString() {
        return "ProofObject{" +
                "storageElementIdentifiers=" + Arrays.toString(storageElementIdentifiers) +
                ", aesKeys=" + Arrays.toString(aesKeys) +
                ", aesKeyNamespaceAttestationProver='" + aesKeyNamespaceAttestationProver + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProofObject that = (ProofObject) o;
        return Arrays.equals(storageElementIdentifiers, that.storageElementIdentifiers) && Arrays.equals(aesKeys, that.aesKeys) && aesKeyNamespaceAttestationProver.equals(that.aesKeyNamespaceAttestationProver);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(aesKeyNamespaceAttestationProver);
        result = 31 * result + Arrays.hashCode(storageElementIdentifiers);
        result = 31 * result + Arrays.hashCode(aesKeys);
        return result;
    }

    /**
     * Method to generate a {@link ProofObject} from a given {@link RTreePolicy}.
     * @param   policy
     *          The {@link RTreePolicy} to prove.
     * @param   publicEntityIdentifierProver
     *          The {@link PublicEntityIdentifier} of the prover.
     *          If the {@link ProofObject} which is generated should be part of another {@link ProofObject},
     *          the {@link PublicEntityIdentifier} of the prover of the full {@link ProofObject} should be provided.
     * @param   privateEntityIdentifierProver
     *          The {@link PrivateEntityIdentifier} of the prover.
     *          If the {@link ProofObject} which is generated should be part of another {@link ProofObject},
     *          the {@link PrivateEntityIdentifier} of the prover of the full {@link ProofObject} should be provided.
     * @param   policyNamespaceAttestationProver
     *          The {@link RTreePolicy} of the {@link NamespaceAttestation} of the prover.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult during the constructing process.
     * @return  The {@link ProofObject}, proving the given {@link RTreePolicy}.
     * @throws  IllegalArgumentException
     *          If the {@link RTreePolicy} could not be proven.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     */
    public static @NotNull ProofObject generateProofObjectForPolicy (
            @NotNull RTreePolicy policy,
            @NotNull PublicEntityIdentifier publicEntityIdentifierProver,
            @NotNull PrivateEntityIdentifier privateEntityIdentifierProver,
            @NotNull RTreePolicy policyNamespaceAttestationProver,
            @NotNull StorageLayer storageLayer)
        throws IllegalArgumentException, IOException {
        return generateProofObjectForPolicy(policy, privateEntityIdentifierProver.getIBEIdentifier(),
                privateEntityIdentifierProver.getWIBEIdentifier(),
                privateEntityIdentifierProver.getNamespaceServiceProviderEmailAddressUserConcatenation(),
                publicEntityIdentifierProver, privateEntityIdentifierProver, policyNamespaceAttestationProver, storageLayer);
    }

    /**
     * Method to extract necessary information from a given {@link Attestation} during the construction process
     * of a {@link ProofObject}.
     * @param   attestation
     *          The {@link Attestation} to extract the information from.
     * @param   ibePKG
     *          The IBE PKG to extract the information with.
     * @param   wibePKG
     *          The WIBE PKG to extract the information with.
     * @param   wibeIdentifier
     *          The IBE identifier to obtain the {@link vrielynckpieterjan.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation} with.
     * @return  The extracted information as a {@link Triple}: <br>
     *          1) a {@link VerificationInformationSegmentAttestation} <br>
     *          2) a {@link ProofInformationSegmentAttestation} <br>
     *          3) a {@link Pair}, representing the two AES keys of the {@link Attestation}.
     * @throws  IllegalArgumentException
     *          If the {@link Attestation} could not be decrypted with the provided arguments.
     */
    private static @NotNull Triple<VerificationInformationSegmentAttestation, ProofInformationSegmentAttestation, Pair<String, String>>
    extractInformationForProofFromAttestation (
            @NotNull Attestation attestation,
            @NotNull Pair<PublicParameters, BigInteger> ibePKG,
            @NotNull Pair<PublicParameters, BigInteger> wibePKG,
            @NotNull RTreePolicy wibeIdentifier)
        throws IllegalArgumentException {
        // Try to decrypt the AES information segment.
        var equallyOrLessStrictPolicies = wibeIdentifier.generateRTreePolicyVariations();
        var encryptedAESInformationSegment = attestation.getFirstLayer().getAesEncryptionInformationSegment();
        var aesEncryptionInformationSegment = new AtomicReference<AESEncryptionInformationSegmentAttestation>(null);

        equallyOrLessStrictPolicies.parallelStream().forEach(rTreePolicy -> {
            if (aesEncryptionInformationSegment.get() != null) return;
            try {
                aesEncryptionInformationSegment.set(encryptedAESInformationSegment.decrypt(
                        new ImmutableTriple<>(wibePKG.getLeft(), wibePKG.getRight(), rTreePolicy)));
            } catch (IllegalArgumentException ignored) {}
        });

        if (aesEncryptionInformationSegment.get() == null) throw new IllegalArgumentException("Information could not be extracted" +
                " from the current attestation for the proof object.");

        // Try to decrypt the AES key information segment.
        var aesKeyInformationSegment = aesEncryptionInformationSegment.get().getAesKeyInformation();

        // Try to decrypt the verification information segment.
        var verificationInformationSegment = attestation.getFirstLayer().getVerificationInformationSegment().decrypt(aesKeyInformationSegment.getLeft());
        var proofInformationSegment = attestation.getFirstLayer().getProofInformationSegment().decrypt(aesKeyInformationSegment.getRight());

        return new ImmutableTriple<>(verificationInformationSegment, proofInformationSegment, aesKeyInformationSegment);
    }

    /**
     * Method to generate a {@link ProofObject} from a given {@link RTreePolicy}.
     * @param   policy
     *          The {@link RTreePolicy} to prove.
     * @param   ibePKG
     *          The IBE PKG of the receiver.
     * @param   wibePKG
     *          The WIBE PKG of the issuer.
     * @param   namespaceAttestationIdentifierReceiver
     *          The String version of the {@link StorageElementIdentifier} used to store
     *          the {@link NamespaceAttestation} with of the receiver in the {@link StorageLayer}.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the receiver.
     * @param   privateEntityIdentifierProver
     *          The {@link PrivateEntityIdentifier} of the prover.
     *          If the {@link ProofObject} which is generated should be part of another {@link ProofObject},
     *          the {@link PrivateEntityIdentifier} of the prover of the full {@link ProofObject} should be provided.
     * @param   policyNamespaceAttestationProver
     *          The {@link RTreePolicy} of the {@link NamespaceAttestation} of the prover.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult during the constructing process.
     * @return  The {@link ProofObject}, proving the given {@link RTreePolicy}.
     * @throws  IllegalArgumentException
     *          If the {@link RTreePolicy} could not be proven.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     */
    private static @NotNull ProofObject generateProofObjectForPolicy (
            @NotNull RTreePolicy policy,
            @NotNull Pair<PublicParameters, BigInteger> ibePKG,
            @NotNull Pair<PublicParameters, BigInteger> wibePKG,
            @NotNull String namespaceAttestationIdentifierReceiver,
            @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
            @NotNull PrivateEntityIdentifier privateEntityIdentifierProver,
            @NotNull RTreePolicy policyNamespaceAttestationProver,
            @NotNull StorageLayer storageLayer)
        throws IllegalArgumentException, IOException {
            logger.info(String.format("Generating a ProofObject for RTreePolicy (%s) by " +
                    "consulting the personal queue of the entity with PublicEntityIdentifier (%s)...", policy, publicEntityIdentifierReceiver));
            var currentStorageElementIdentifier = new StorageElementIdentifier(namespaceAttestationIdentifierReceiver);
            int curIndexInPersonalQueue = 0;
            while (true) {
                Set<Attestation> retrievedAttestations = new HashSet<>();
                if (curIndexInPersonalQueue == 0) retrievedAttestations.addAll(
                        storageLayer.retrieve(currentStorageElementIdentifier, NamespaceAttestation.class));
                else retrievedAttestations.addAll(storageLayer.retrieve(currentStorageElementIdentifier, Attestation.class));

                boolean queueAttestationAtCurIndexFound = false;
                for (Attestation retrievedAttestation : retrievedAttestations) {
                    if (retrievedAttestation.isRevoked(storageLayer) ||
                            !retrievedAttestation.areSecondAndThirdLayerValid(publicEntityIdentifierReceiver)) continue;

                    // Proven that the receivers match: update the pointers.
                    curIndexInPersonalQueue ++;
                    currentStorageElementIdentifier = retrievedAttestation.getThirdLayer().decrypt(
                            publicEntityIdentifierReceiver).getRight();
                    queueAttestationAtCurIndexFound = true;

                    // Try to extract even more information from the attestation.
                    try {
                        var extractedInformationAttestation = extractInformationForProofFromAttestation(
                                retrievedAttestation, ibePKG, wibePKG, policy);
                        var extractedPolicy = extractedInformationAttestation.getLeft().getRTreePolicy();
                        var newPartStorageElementIdentifiers = new StorageElementIdentifier[]{retrievedAttestation.getStorageLayerIdentifier()};
                        var newPartAESKeys = new String[]{extractedInformationAttestation.getRight().getLeft()};

                        if (retrievedAttestation instanceof NamespaceAttestation) {
                            var aesKeyNamespaceAttestationProver = retrieveFirstAESKeyNamespaceAttestationProver(
                                    privateEntityIdentifierProver, policyNamespaceAttestationProver,
                                    storageLayer);
                            return new ProofObject(newPartStorageElementIdentifiers, newPartAESKeys, aesKeyNamespaceAttestationProver);
                        }

                        var lessStrictProof = generateProofObjectForPolicy(
                                extractedPolicy, extractedInformationAttestation.getMiddle().getIBEPKG(),
                                extractedInformationAttestation.getMiddle().getWIBEPKG(),
                                extractedInformationAttestation.getLeft().getPublicEntityIdentifierIssuer().getNamespaceServiceProviderEmailAddressUserConcatenation(),
                                extractedInformationAttestation.getLeft().getPublicEntityIdentifierIssuer(),
                                privateEntityIdentifierProver, policyNamespaceAttestationProver, storageLayer);
                        return new ProofObject(ArrayUtils.add(lessStrictProof.storageElementIdentifiers, newPartStorageElementIdentifiers[0]),
                                ArrayUtils.add(lessStrictProof.aesKeys, newPartAESKeys[0]), lessStrictProof.aesKeyNamespaceAttestationProver);


                    } catch (IllegalArgumentException ignored) {}

                    break;
                }

                if (!queueAttestationAtCurIndexFound) throw new IllegalArgumentException(String.format(
                        "The %sth Attestation in the personal queue of the entity with PublicEntityIdentifier (%s)" +
                                " could not be found.", curIndexInPersonalQueue, publicEntityIdentifierReceiver));
            }
    }

    /**
     * Method to retrieve the first AES key of the {@link NamespaceAttestation} of the prover
     * to use during the constructing process of a {@link ProofObject}.
     * @param   privateEntityIdentifierProver
     *          The {@link PrivateEntityIdentifier} of the prover.
     * @param   storageLayer
     *          The {@link StorageLayer} to consult.
     * @param   policyNamespaceAttestationProver
     *          The {@link RTreePolicy} for the {@link NamespaceAttestation} of the owner of the resources.
     * @return  The first AES key of the {@link NamespaceAttestation} of the prover.
     * @throws  IllegalArgumentException
     *          If the {@link PrivateEntityIdentifier} is invalid.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     */
    private static @NotNull String retrieveFirstAESKeyNamespaceAttestationProver (
            @NotNull PrivateEntityIdentifier privateEntityIdentifierProver,
            @NotNull RTreePolicy policyNamespaceAttestationProver,
            @NotNull StorageLayer storageLayer)
        throws IllegalArgumentException, IOException {
        Set<NamespaceAttestation> retrievedNamespaceAttestations = storageLayer.retrieve(
                new StorageElementIdentifier(privateEntityIdentifierProver.getNamespaceServiceProviderEmailAddressUserConcatenation()),
                NamespaceAttestation.class);
        for (NamespaceAttestation namespaceAttestation : retrievedNamespaceAttestations) {
            try {
                var encryptedAESInformationSegment = namespaceAttestation.getFirstLayer().getAesEncryptionInformationSegment();
                var encryptionInformationSegment = encryptedAESInformationSegment
                        .decrypt(privateEntityIdentifierProver, policyNamespaceAttestationProver);
                var aesKeys = encryptionInformationSegment.getAesKeyInformation();
                return aesKeys.getLeft();
            } catch (IllegalArgumentException ignored) {}
        }

        throw new IllegalArgumentException("NamespaceAttestation prover not found.");
    }
}
