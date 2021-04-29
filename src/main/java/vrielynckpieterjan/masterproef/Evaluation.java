package vrielynckpieterjan.masterproef;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroon;
import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroonManager;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.proof.ProofObject;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;
import vrielynckpieterjan.masterproef.storagelayer.dht.DHTStorageLayer;
import vrielynckpieterjan.masterproef.storagelayer.map.HashMapStorageLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

import static vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight.WRITE;

public class Evaluation {

    private final static List<Pair<PrivateEntityIdentifier, PublicEntityIdentifier>> generatedEntityIdentifiers = Collections.synchronizedList(new ArrayList<>());
    private final static List<Pair<RevocationSecret, RevocationCommitment>> generatedRevocationCommitmentsIssuersNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static List<Pair<RevocationSecret, RevocationCommitment>> generatedRevocationCommitmentsReceiversNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static List<RTreePolicy> generatedPoliciesNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static List<StorageElementIdentifier> generatedNextStorageElementIdentifierNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static List<IssuerPartNamespaceAttestation> generatedIssuerPartsNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static List<NamespaceAttestation> generatedNamespaceAttestations = Collections.synchronizedList(new ArrayList<>());
    private final static InetSocketAddress referenceAPILayer = new InetSocketAddress("localhost", 5678);

    public static void main(String[] args) throws IOException {
        performEntityIdentifiersTest();
        performRevocationCommitmentGenerationTest();
        performPolicyGenerationTest();
        performIssuerPartNamespaceAttestationGenerationTest();
        performStorageElementIdentifierNextQueueElementGenerationTest();
        performReceiverPartNamespaceAttestationGenerationTest();
        fullyDecryptOneAttestationTest();
        performMacaroonGenerationAndVerificationTest();

        performProofObjectTestSamePolicy();
        performProofObjectTestDifferentPolicy();
    }

    private static void fullyDecryptOneAttestationTest() {
        var attestation = generatedNamespaceAttestations.get(0);
        var issuer = generatedEntityIdentifiers.get(0);
        var receiver = issuer;
        var policy = generatedPoliciesNamespaceAttestations.get(0);
        runTest(iteration -> {
            var aesKeyInformation = attestation.getFirstLayer().getAesEncryptionInformationSegment()
                    .decrypt(receiver.getLeft(), policy);
        }, "Decrypting AES key information segment one attestation", 100);

        var aesKeyInformation = attestation.getFirstLayer().getAesEncryptionInformationSegment()
                .decrypt(receiver.getLeft(), policy);
        runTest(iteration -> {
            attestation.getFirstLayer().getProofInformationSegment().decrypt(aesKeyInformation.getAesKeyInformation().getRight());
        }, "Decrypting AES encrypted segment one attestation", 100);

        var verificationInformationSegment = attestation.getFirstLayer().getVerificationInformationSegment().decrypt(aesKeyInformation.getAesKeyInformation().getLeft());
        var privateKey = verificationInformationSegment.getEncryptedEmpiricalPrivateRSAKey().decrypt(verificationInformationSegment.getPublicEntityIdentifierIssuer());
        var publicKey = attestation.getFirstLayer().getEmpiricalPublicKey();
        runTest(iteration -> {
            attestation.isValid(privateKey, publicKey, attestation.getFirstLayer().getPublicEntityIdentifierReceiver());
        }, "Checking if attestation is valid using the ephemeral RSA keypair", 100);
    }

    private static void performProofObjectTestDifferentPolicy() throws IOException {
        // Generate the policy.
        var originalPolicy = new RTreePolicy(generatedPoliciesNamespaceAttestations.get(0), WRITE, RandomStringUtils.randomAlphanumeric(20));
        var policies = new ArrayList<RTreePolicy>();
        for (var i = 0; i < 100; i ++) {
            policies.add(originalPolicy);
            originalPolicy = new RTreePolicy(originalPolicy, WRITE, RandomStringUtils.randomAlphanumeric(20));
        }

        // Generate all the necessary attestations and obtain their keys.
        var attestations = new ArrayList<Attestation>();
        var keysAttestations = new ArrayList<Pair<String, String>>();
        for (var i = 0; i < 100; i ++) {
            var issuerIdentifiers = generatedEntityIdentifiers.get(Math.max(i - 1, 0));
            var receiverIdentifiers = generatedEntityIdentifiers.get(i);
            var issuerPartAttestation = new IssuerPartNamespaceAttestation(
                    issuerIdentifiers.getLeft(),
                    issuerIdentifiers.getRight(),
                    receiverIdentifiers.getRight(),
                    new RevocationCommitment(new RevocationSecret()), policies.get(i), referenceAPILayer);
            var attestation = new Attestation(generatedNextStorageElementIdentifierNamespaceAttestations.get(i),
                    issuerPartAttestation, new RevocationCommitment(new RevocationSecret()),
                    new StorageElementIdentifier(),
                    receiverIdentifiers.getLeft());
            attestations.add(attestation);

            var aesKeysSegment = attestation.getFirstLayer().getAesEncryptionInformationSegment().decrypt(receiverIdentifiers.getLeft(), policies.get(i));
            keysAttestations.add(aesKeysSegment.getAesKeyInformation());
        }

        // Obtain the first AES keys of the namespace attestations.
        var firstAESKeysNamespaceAttestations = new ArrayList<String>();
        for (var i = 0; i < 100; i ++) {
            var namespaceAttestation = generatedNamespaceAttestations.get(i);
            var policyNamespaceAttestation = generatedPoliciesNamespaceAttestations.get(i);
            var receiverNamespaceAttestation = generatedEntityIdentifiers.get(i);
            var aesKeysSegment = namespaceAttestation.getFirstLayer().getAesEncryptionInformationSegment()
                    .decrypt(receiverNamespaceAttestation.getLeft(), policyNamespaceAttestation);
            firstAESKeysNamespaceAttestations.add(aesKeysSegment.getAesKeyInformation().getLeft());
        }

        // Storing everything in the storage layer.
        var storageLayer = new HashMapStorageLayer();
        generatedNamespaceAttestations.forEach(storageLayer::put);
        attestations.forEach(storageLayer::put);

        // The actual test.
        var proofs = new ArrayList<ProofObject>();
        double timer;
        for (var i = 0; i < 30; i ++) {
            timer = System.currentTimeMillis();
            var proof = ProofObject.generateProofObject(attestations.get(i),
                    keysAttestations.get(i).getLeft(),
                    keysAttestations.get(i).getRight(),
                    firstAESKeysNamespaceAttestations.get(i),
                    storageLayer);
            System.out.printf("[%e milliseconds]\tProof object constructed for %s attestation(s) (different policy)%n",
                    System.currentTimeMillis() - timer, i + 1);
            proofs.add(proof);
        }

        for (var i = 0; i < 30; i ++) {
            timer = System.currentTimeMillis();
            proofs.get(i).verify(storageLayer);
            System.out.printf("[%e milliseconds]\tProof object verified for %s attestation(s) (different policy)%n",
                    System.currentTimeMillis() - timer, i + 1);
        }
    }

    private static void performProofObjectTestSamePolicy() throws IOException {
        // Generate the policy.
        var policy = new RTreePolicy(generatedPoliciesNamespaceAttestations.get(0), WRITE, RandomStringUtils.randomAlphanumeric(20));

        // Generate all the necessary attestations and obtain their keys.
        var attestations = new ArrayList<Attestation>();
        var keysAttestations = new ArrayList<Pair<String, String>>();
        for (var i = 0; i < 100; i ++) {
            var issuerIdentifiers = generatedEntityIdentifiers.get(Math.max(i - 1, 0));
            var receiverIdentifiers = generatedEntityIdentifiers.get(i);
            var issuerPartAttestation = new IssuerPartNamespaceAttestation(
                    issuerIdentifiers.getLeft(),
                    issuerIdentifiers.getRight(),
                    receiverIdentifiers.getRight(),
                    new RevocationCommitment(new RevocationSecret()), policy, referenceAPILayer);
            var attestation = new Attestation(generatedNextStorageElementIdentifierNamespaceAttestations.get(i),
                    issuerPartAttestation, new RevocationCommitment(new RevocationSecret()),
                    new StorageElementIdentifier(),
                    receiverIdentifiers.getLeft());
            attestations.add(attestation);

            var aesKeysSegment = attestation.getFirstLayer().getAesEncryptionInformationSegment().decrypt(receiverIdentifiers.getLeft(), policy);
            keysAttestations.add(aesKeysSegment.getAesKeyInformation());
        }

        // Obtain the first AES keys of the namespace attestations.
        var firstAESKeysNamespaceAttestations = new ArrayList<String>();
        for (var i = 0; i < 100; i ++) {
            var namespaceAttestation = generatedNamespaceAttestations.get(i);
            var policyNamespaceAttestation = generatedPoliciesNamespaceAttestations.get(i);
            var receiverNamespaceAttestation = generatedEntityIdentifiers.get(i);
            var aesKeysSegment = namespaceAttestation.getFirstLayer().getAesEncryptionInformationSegment()
                    .decrypt(receiverNamespaceAttestation.getLeft(), policyNamespaceAttestation);
            firstAESKeysNamespaceAttestations.add(aesKeysSegment.getAesKeyInformation().getLeft());
        }

        // Storing everything in the storage layer.
        var storageLayer = new HashMapStorageLayer();
        generatedNamespaceAttestations.forEach(storageLayer::put);
        attestations.forEach(storageLayer::put);

        // The actual test.
        var proofs = new ArrayList<ProofObject>();
        double timer;
        for (var i = 0; i < 30; i ++) {
            timer = System.currentTimeMillis();
            var proof = ProofObject.generateProofObject(attestations.get(i),
                    keysAttestations.get(i).getLeft(),
                    keysAttestations.get(i).getRight(),
                    firstAESKeysNamespaceAttestations.get(i),
                    storageLayer);
            System.out.printf("[%e milliseconds]\tProof object constructed for %s attestation(s) (same policy)%n",
                    System.currentTimeMillis() - timer, i + 1);
            proofs.add(proof);
        }

        for (var i = 0; i < 30; i ++) {
            timer = System.currentTimeMillis();
            proofs.get(i).verify(storageLayer);
            System.out.printf("[%e milliseconds]\tProof object verified for %s attestation(s) (same policy)%n",
                    System.currentTimeMillis() - timer, i + 1);
        }
    }

    private static void performMacaroonGenerationAndVerificationTest() {
        var macaroonManager = new APILayerMacaroonManager();
        var policies = new ArrayList<>();
        for (var i = 0; i < 100; i ++) policies.add(new RTreePolicy(WRITE, RandomStringUtils.randomAlphanumeric(20)));
        var macaroons = new ArrayList<>();
        runTest(iteration -> {
            macaroons.add(macaroonManager.registerPolicy((RTreePolicy) policies.get(iteration)));
        }, "Converting RTreePolicy to APILayerMacaroonManager", 100);
        runTest(iteration -> {
            macaroonManager.returnVerifiedPolicy((APILayerMacaroon) macaroons.get(iteration));
        }, "Verifying APILayerMacaroon", 100);
    }

    private static void performStorageElementIdentifierNextQueueElementGenerationTest() {
        runTest(iteration -> {
            var storageElementIdentifier = new StorageElementIdentifier();
            generatedNextStorageElementIdentifierNamespaceAttestations.add(storageElementIdentifier);
        }, "Generating storage element identifier", 100);
        assert(generatedNextStorageElementIdentifierNamespaceAttestations.size() == 100);
    }

    private static void performReceiverPartNamespaceAttestationGenerationTest() {
        runTest(iteration -> {
            var firstLayer = generatedIssuerPartsNamespaceAttestations.get(iteration);
            var storageElementIdentifierNextQueueObject = generatedNextStorageElementIdentifierNamespaceAttestations.get(iteration);
            var revocationObjects = generatedRevocationCommitmentsReceiversNamespaceAttestations.get(iteration);
            var receiver = generatedEntityIdentifiers.get(iteration);

            var attestation = new NamespaceAttestation(firstLayer, revocationObjects.getRight(), storageElementIdentifierNextQueueObject,
                    receiver.getRight(), receiver.getLeft());
            generatedNamespaceAttestations.add(attestation);
        }, "Generating receiver part attestation", 100);
        assert(generatedNamespaceAttestations.size() == 100);
    }

    private static void performIssuerPartNamespaceAttestationGenerationTest() {
        runTest(iteration -> {
            var issuer = generatedEntityIdentifiers.get(0);
            var receiver = generatedEntityIdentifiers.get(iteration);
            var revocationObjects = generatedRevocationCommitmentsIssuersNamespaceAttestations.get(iteration);
            var policy = generatedPoliciesNamespaceAttestations.get(iteration);
            var issuerPartNamespaceAttestation = new IssuerPartNamespaceAttestation(
                    issuer.getLeft(), issuer.getRight(), receiver.getRight(), revocationObjects.getRight(), policy,
                    referenceAPILayer);
            generatedIssuerPartsNamespaceAttestations.add(issuerPartNamespaceAttestation);
        }, "Generating issuer part attestation", 100);
        assert(generatedIssuerPartsNamespaceAttestations.size() == 100);

        
    }

    private static void performPolicyGenerationTest() {
        runTest(iteration -> {
            var issuerEntity = generatedEntityIdentifiers.get(0);
            var receiverEntity = generatedEntityIdentifiers.get(iteration);

            var policy = new RTreePolicy(WRITE, issuerEntity.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation(),
                    receiverEntity.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
            generatedPoliciesNamespaceAttestations.add(policy);
        }, "Generating policy", 100);
        assert(generatedPoliciesNamespaceAttestations.size() == 100);
    }

    private static void performRevocationCommitmentGenerationTest() {
        runTest(iteration -> {
            var selectedList = (iteration >= 100)? generatedRevocationCommitmentsReceiversNamespaceAttestations:generatedRevocationCommitmentsIssuersNamespaceAttestations;

            var revocationSecret = new RevocationSecret();
            var revocationCommitment = new RevocationCommitment(revocationSecret);
            selectedList.add(new ImmutablePair<>(revocationSecret, revocationCommitment));
        }, "Generating revocation secret and commitment", 200);
        assert(generatedRevocationCommitmentsReceiversNamespaceAttestations.size() ==
                generatedRevocationCommitmentsIssuersNamespaceAttestations.size());
        assert(generatedRevocationCommitmentsReceiversNamespaceAttestations.size() == 100);
    }

    private static void performEntityIdentifiersTest() {
        runTest((iteration) -> generatedEntityIdentifiers.add(EntityIdentifier.generateEntityIdentifierPair(RandomStringUtils.randomAlphanumeric(20))),
                "Generating entity identifier pair", 100);
        assert(generatedEntityIdentifiers.size() == 100);
    }

    private static void runTest(@NotNull Consumer<Integer> consumer, @NotNull String description, int amountOfIterations) {
        double averageTime = 0.0;
        for (var i = 0; i < amountOfIterations; i ++) {
            var time = System.currentTimeMillis();
            consumer.accept(i);
            time = System.currentTimeMillis() - time;
            averageTime += time;
        }
        averageTime /= amountOfIterations;
        System.out.printf("[%e milliseconds]\t%s%n", averageTime, description);
    }
}
