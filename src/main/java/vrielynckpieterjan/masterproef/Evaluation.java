package vrielynckpieterjan.masterproef;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;

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

    public static void main(String[] args) {
        performEntityIdentifiersTest();
        performRevocationCommitmentGenerationTest();
        performPolicyGenerationTest();
        performIssuerPartNamespaceAttestationGenerationTest();
        performStorageElementIdentifierNextQueueElementGenerationTest();
        performReceiverPartNamespaceAttestationGenerationTest();
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
