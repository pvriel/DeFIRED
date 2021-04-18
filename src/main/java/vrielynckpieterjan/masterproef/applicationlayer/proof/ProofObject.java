package vrielynckpieterjan.masterproef.applicationlayer.proof;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

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
    protected ProofObject(StorageElementIdentifier[] storageElementIdentifiers,
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

        logger.info(String.format("Verifying that the prover with PublicEntityIdentifier (%s) is hosting" +
                " his personal queue...", publicEntityIdentifierProver));
        verifyPersonalQueue(namespaceAttestationPairProver.getLeft(), storageElementIdentifiers[storageElementIdentifiers.length - 1],
                storageLayer);

        logger.info(String.format("ProofObject (%s) verified.", this));
        return currentPolicy;
    }

    /**
     * Method to check if the prover hosts an {@link Attestation} with the provided {@link StorageElementIdentifier}
     * in his personal queue.
     * @param   curAttestation
     *          The final {@link Attestation} of the proof.
     * @param   storageElementIdentifierToFind
     *          The {@link StorageElementIdentifier} of the {@link Attestation} to find in the personal queue of the prover.
     * @param   storageLayer
     *          The {@link StorageLayer}.
     * @throws  IllegalArgumentException
     *          If the {@link Attestation} could not be found.
     * @throws  IOException
     *          If an IO-related problem occurred while consulting the {@link StorageLayer}.
     */
    private static void verifyPersonalQueue(@NotNull Attestation curAttestation,
                                            @NotNull StorageElementIdentifier storageElementIdentifierToFind,
                                            @NotNull StorageLayer storageLayer) throws IllegalArgumentException, IOException {
        var publicEntityIdentifierProver = curAttestation.getFirstLayer().getPublicEntityIdentifierReceiver();
        var personalQueueProver = storageLayer.getPersonalQueueUser(publicEntityIdentifierProver);

        while (!curAttestation.getStorageLayerIdentifier().equals(storageElementIdentifierToFind)) {
            curAttestation = personalQueueProver.next();
        }
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
     * {@link StorageElementIdentifier}, from which the unencrypted {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation}
     * can be extracted using the provided AES key.
     * The latter part is done to extract the {@link RTreePolicy} from the {@link Attestation} instance.
     * @param   storageElementIdentifier
     *          The {@link StorageElementIdentifier} to find the {@link Attestation} with.
     * @param   firstAESKeyAttestation
     *          The AES key to decrypt the encrypted version of the {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation} of
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
     * Method to generate a {@link ProofObject} object for a given {@link Attestation}.
     * @param   attestation
     *          The final {@link Attestation} of the proof.
     * @param   firstAESKey
     *          The first AES key of the provided {@link Attestation}.
     * @param   secondAESKey
     *          The second AES key of the provided {@link Attestation}.
     * @param   aesKeyNamespaceAttestationProver
     *          The first AES key for the namespace attestation of the prover.
     * @param   storageLayer
     *          The {@link StorageLayer}.
     * @return  The {@link ProofObject}.
     * @throws  IllegalArgumentException
     *          If the provided {@link Attestation} is not part of a proof.
     * @throws  IOException
     *          If an IO-related problem occurred while consulting the {@link StorageLayer}.
     */
    public static @NotNull ProofObject generateProofObject
            (@NotNull Attestation attestation,
             @NotNull String firstAESKey,
             @NotNull String secondAESKey,
             @NotNull String aesKeyNamespaceAttestationProver,
             @NotNull StorageLayer storageLayer) throws IllegalArgumentException, IOException {
        if (attestation instanceof NamespaceAttestation) {
            return new ProofObject(new StorageElementIdentifier[]{attestation.getStorageLayerIdentifier()},
                    new String[]{firstAESKey}, aesKeyNamespaceAttestationProver);
        }
        // 1. Retrieve the necessary information from the attestation.
        var verificationInformationSegment = attestation.getFirstLayer()
                .getVerificationInformationSegment().decrypt(firstAESKey);
        var proverInformationSegment = attestation.getFirstLayer()
                .getProofInformationSegment().decrypt(secondAESKey);
        var policy = verificationInformationSegment.getRTreePolicy();
        var publicEntityIdentifier = verificationInformationSegment.getPublicEntityIdentifierIssuer();
        var ibePKG = proverInformationSegment.getIBEPKG();

        // 2. Find the previous attestation of the proof.
        var informationPreviousAttestationProof = findPreviousAttestationForProof(
                policy, publicEntityIdentifier, ibePKG, storageLayer);
        var previousAttestation = informationPreviousAttestationProof.getLeft();
        var firstAESKeyPreviousAttestation = informationPreviousAttestationProof.getMiddle();
        var secondAESKeyPreviousAttestation = informationPreviousAttestationProof.getRight();

        // 3. Recursively generate the proof object.
        var proofObjectPreviousAttestationsProof = generateProofObject(previousAttestation,
                firstAESKeyPreviousAttestation, secondAESKeyPreviousAttestation, aesKeyNamespaceAttestationProver, storageLayer);
        return new ProofObject(ArrayUtils.add(proofObjectPreviousAttestationsProof.storageElementIdentifiers, attestation.getStorageLayerIdentifier()),
                ArrayUtils.add(proofObjectPreviousAttestationsProof.aesKeys, firstAESKey),
                aesKeyNamespaceAttestationProver);
    }

    /**
     * Method to find the information about the previous {@link Attestation} of the proof.
     * @param   policy
     *          The {@link RTreePolicy} of the current {@link Attestation} of the proof.
     * @param   publicEntityIdentifier
     *          The {@link PublicEntityIdentifier} of the receiver of the previous {@link Attestation} of the proof.
     * @param   ibePKG
     *          The IBE PKG of the receiver of the previous {@link Attestation} of the proof.
     * @param   storageLayer
     *          The {@link StorageLayer}.
     * @return  A {@link Triple}, containing the found {@link Attestation} together with its two AES keys.
     * @throws  IllegalArgumentException
     *          If the previous {@link Attestation} of the proof could not be found.
     * @throws  IOException
     *          If an IO-related exception occurred while consulting the {@link StorageLayer}.
     */
    private static @NotNull Triple<Attestation, String, String> findPreviousAttestationForProof(@NotNull RTreePolicy policy,
            @NotNull PublicEntityIdentifier publicEntityIdentifier, @NotNull Pair<PublicParameters, BigInteger> ibePKG,
            @NotNull StorageLayer storageLayer) throws IllegalArgumentException, IOException {
        // 1. Find the personal queue of the user.
        var personalQueue = storageLayer.getPersonalQueueUser(publicEntityIdentifier);

        // 2. Generate the possible policies for the decryption process.
        var policies = policy.generateRTreePolicyVariations();

        // 3. Iterate over the personal queue, until the previous attestation for the proof is found.
        while (true) {
            var attestation = personalQueue.next();
            System.out.println(attestation);
            var encryptedAESEncryptionInformationSegment = attestation.getFirstLayer().getAesEncryptionInformationSegment();

            try {
                AtomicReference<AESEncryptionInformationSegmentAttestation> aesEncryptionInformationSegment = new AtomicReference<>();
                policies.parallelStream().forEach(rTreePolicy -> {
                    if (aesEncryptionInformationSegment.get() != null) return;
                    try {
                        aesEncryptionInformationSegment.set(encryptedAESEncryptionInformationSegment.decrypt(
                                new ImmutableTriple<>(ibePKG.getLeft(), ibePKG.getRight(), rTreePolicy.toString())));
                    } catch (IllegalArgumentException ignored) {}
                });
                if (aesEncryptionInformationSegment.get() == null) continue;
                // Found! Return the necessary information.
                var aesKeys = aesEncryptionInformationSegment.get().getAesKeyInformation();
                return new ImmutableTriple<>(attestation, aesKeys.getLeft(), aesKeys.getRight());
            } catch (IllegalArgumentException ignored) {}
        }
    }
}
