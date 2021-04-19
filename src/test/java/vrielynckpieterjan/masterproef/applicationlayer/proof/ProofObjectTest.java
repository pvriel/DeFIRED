package vrielynckpieterjan.masterproef.applicationlayer.proof;

import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.dht.DHTStorageLayer;
import vrielynckpieterjan.masterproef.storagelayer.map.HashMapStorageLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class ProofObjectTest {

    @Test
    /**
     * One big test case, which basically tests the entire framework except for the API and the storage layers:
     * 1)   Constructs a chain of attestations (cloud storage service provider --(namespace attestation)--> user A
     *          --(attestation)--> user B --(attestation)--> user C at publishes the constructed objects in the
     *          {@link vrielynckpieterjan.masterproef.storagelayer.StorageLayer}.
     * 2)   Asks user C to construct a proof object for the chain of attestations.
     * 3)   Verifies the proof object.
     * 4)   Checks if the proof object can still be verified if one of the attestations is revoked.
     */
    void test() throws IOException {
        long counter;

        // 1) Generate three users and a cloud storage service provider.
        counter = System.currentTimeMillis();
        var cloudStorageProvider = EntityIdentifier.generateEntityIdentifierPair(
                "cloudStorageServiceProvider");
        var userA = EntityIdentifier.generateEntityIdentifierPair("userA");
        var userB = EntityIdentifier.generateEntityIdentifierPair("userB");
        var userC = EntityIdentifier.generateEntityIdentifierPair("userC");
        System.out.println(String.format("Entity identifiers generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));
        System.out.println("The generate PublicEntityIdentifiers:");
        System.out.println(String.format("Cloud:\t%s", cloudStorageProvider.getRight()));
        System.out.println(String.format("userA:\t%s", userA.getRight()));
        System.out.println(String.format("userB:\t%s", userB.getRight()));
        System.out.println(String.format("userC:\t%s", userC.getRight()));


        // 2) Generate the policies for each (namespace) attestation.
        counter = System.currentTimeMillis();
        var namespacePolicyUserA = new RTreePolicy(PolicyRight.WRITE, "A");
        var namespacePolicyUserB = new RTreePolicy(PolicyRight.WRITE, "B");
        var namespacePolicyUserC = new RTreePolicy(PolicyRight.WRITE, "C");
        var userAToUserBPolicy = new RTreePolicy(namespacePolicyUserA, PolicyRight.READ, "B");
        var userBToUserCPolicy = new RTreePolicy(userAToUserBPolicy, PolicyRight.WRITE, "C");
        System.out.println(String.format("Policies generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 3) Generate the storage identifiers for each (namespace) attestation.
        counter = System.currentTimeMillis();
        var namespaceAttestationStorageIdentifierUserA = new StorageElementIdentifier(userA.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
        var namespaceAttestationStorageIdentifierUserB = new StorageElementIdentifier(userB.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
        var namespaceAttestationStorageIdentifierUserC = new StorageElementIdentifier(userC.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
        var shareAttestationStorageIdentifier = new StorageElementIdentifier("userAtoUserB");
        var delegateAttestationStorageIdentifier = new StorageElementIdentifier("userBtoUserC");
        System.out.println(String.format("Storage identifiers generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 4) Generate the revocation commitments.
        counter = System.currentTimeMillis();
        var serviceProviderUserARevocationSecret = new RevocationSecret("serviceProviderUserARevocationSecret");
        var serviceProviderUserBRevocationSecret = new RevocationSecret("serviceProviderUserBRevocationSecret");
        var serviceProviderUserCRevocationSecret = new RevocationSecret("serviceProviderUserCRevocationSecret");
        var userANamespaceAttestationRevocationSecret = new RevocationSecret("userANamespaceAttestationRevocationSecret");
        var userBNamespaceAttestationRevocationSecret = new RevocationSecret("userBNamespaceAttestationRevocationSecret");
        var userCNamespaceAttestationRevocationSecret = new RevocationSecret("userCNamespaceAttestationRevocationSecret");
        var userAShareAttestationRevocationSecret = new RevocationSecret("userAShareAttestationRevocationSecret");
        var userBShareAttestationRevocationSecret = new RevocationSecret("userBShareAttestationRevocationSecret");
        var userBDelegationAttestationRevocationSecret = new RevocationSecret("userBDelegationAttestationRevocationSecret");
        var userCDelegationAttestationRevocationSecret = new RevocationSecret("userCDelegationAttestationRevocationSecret");

        var serviceProviderUserARevocationCommitment = new RevocationCommitment(serviceProviderUserARevocationSecret);
        var serviceProviderUserBRevocationCommitment = new RevocationCommitment(serviceProviderUserBRevocationSecret);
        var serviceProviderUserCRevocationCommitment = new RevocationCommitment(serviceProviderUserCRevocationSecret);
        var userANamespaceAttestationRevocationCommitment = new RevocationCommitment(userANamespaceAttestationRevocationSecret);
        var userBNamespaceAttestationRevocationCommitment = new RevocationCommitment(userBNamespaceAttestationRevocationSecret);
        var userCNamespaceAttestationRevocationCommitment = new RevocationCommitment(userCNamespaceAttestationRevocationSecret);
        var userAShareAttestationRevocationCommitment = new RevocationCommitment(userAShareAttestationRevocationSecret);
        var userBShareAttestationRevocationCommitment = new RevocationCommitment(userBShareAttestationRevocationSecret);
        var userBDelegationAttestationRevocationCommitment = new RevocationCommitment(userBDelegationAttestationRevocationSecret);
        var userCDelegationAttestationRevocationCommitment = new RevocationCommitment(userCDelegationAttestationRevocationSecret);
        System.out.println(String.format("Revocation secrets and commitments generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 5) For simplicity reasons: only use one InetSocketAddress.
        var referenceAPILayer = new InetSocketAddress("localhost", 5678);

        // 6) Create the issuer's part of the attestations.
        counter = System.currentTimeMillis();
        var serviceProviderPartNamespaceAttestationUserA = new IssuerPartNamespaceAttestation(cloudStorageProvider.getLeft(),
                cloudStorageProvider.getRight(), userA.getRight(), serviceProviderUserARevocationCommitment,
                namespacePolicyUserA, referenceAPILayer);
        var serviceProviderPartNamespaceAttestationUserB = new IssuerPartNamespaceAttestation(cloudStorageProvider.getLeft(),
                cloudStorageProvider.getRight(), userB.getRight(), serviceProviderUserBRevocationCommitment,
                namespacePolicyUserB, referenceAPILayer);
        var serviceProviderPartNamespaceAttestationUserC = new IssuerPartNamespaceAttestation(cloudStorageProvider.getLeft(),
                cloudStorageProvider.getRight(), userC.getRight(), serviceProviderUserCRevocationCommitment,
                namespacePolicyUserC, referenceAPILayer);
        var userAPartShareAttestation = new IssuerPartAttestation(userA.getLeft(), userA.getRight(),
                userB.getRight(), userAShareAttestationRevocationCommitment, userAToUserBPolicy);
        var userBPartDelegationAttestation = new IssuerPartAttestation(userB.getLeft(), userB.getRight(),
                userC.getRight(), userBDelegationAttestationRevocationCommitment, userBToUserCPolicy);
        System.out.println(String.format("Issuer's parts generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 7) create the attestations.
        counter = System.currentTimeMillis();
        var namespaceAttestationA = new NamespaceAttestation(
                serviceProviderPartNamespaceAttestationUserA, userANamespaceAttestationRevocationCommitment,
                namespaceAttestationStorageIdentifierUserA, userA.getRight(), userA.getLeft());
        var namespaceAttestationB = new NamespaceAttestation(
                serviceProviderPartNamespaceAttestationUserB, userBNamespaceAttestationRevocationCommitment,
                shareAttestationStorageIdentifier, userB.getRight(), userB.getLeft());
        var namespaceAttestationC = new NamespaceAttestation(
                serviceProviderPartNamespaceAttestationUserC, userCNamespaceAttestationRevocationCommitment,
                delegateAttestationStorageIdentifier, userC.getRight(), userC.getLeft());
        var shareAttestation = new Attestation(shareAttestationStorageIdentifier, userAPartShareAttestation,
                userBShareAttestationRevocationCommitment, namespaceAttestationStorageIdentifierUserB, userB.getLeft());
        var delegateAttestation = new Attestation(delegateAttestationStorageIdentifier, userBPartDelegationAttestation,
                userCDelegationAttestationRevocationCommitment, namespaceAttestationStorageIdentifierUserC, userC.getLeft());
        System.out.println(String.format("Attestations generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 8) Initialized the storage layer.
        counter = System.currentTimeMillis();
        var storageLayerUserA = new DHTStorageLayer(userA.getRight(), 5678);
        var storageLayerUserB = new DHTStorageLayer(userB.getRight(), 5679, storageLayerUserA);
        var storageLayerUserC = new DHTStorageLayer(userC.getRight(), 5680, storageLayerUserA, storageLayerUserB);
        System.out.println(String.format("DHTStorageLayers initialized (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        counter = System.currentTimeMillis();
        storageLayerUserA.put(namespaceAttestationA);
        storageLayerUserB.put(namespaceAttestationB);
        storageLayerUserC.put(namespaceAttestationC);
        storageLayerUserB.put(shareAttestation);
        storageLayerUserC.put(delegateAttestation);
        System.out.println(String.format("Generated Attestations stored in the DHT (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));


        // 9) Generate the proof object manually.
        counter = System.currentTimeMillis();
        Attestation[] attestationsForProofObject = new Attestation[]{namespaceAttestationA, shareAttestation, delegateAttestation,
            namespaceAttestationC};
        RTreePolicy[] attestationPolicies = new RTreePolicy[]{namespacePolicyUserA, userAToUserBPolicy, userBToUserCPolicy,
            namespacePolicyUserC};
        PrivateEntityIdentifier[] privateEntityIdentifiersReceivers = new PrivateEntityIdentifier[]{
            userA.getLeft(), userB.getLeft(), userC.getLeft(), userC.getLeft()};
        StorageElementIdentifier[] storageElementIdentifiersForProofObject = new StorageElementIdentifier[4];
        String[] firstAESKeysForProofObject = new String[4];
        String[] secondAESKeysForProofObject = new String[4];
        for (int i = 0; i < attestationsForProofObject.length; i ++) {
            IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> encryptedAESEncryptionInformationSegment =
                    attestationsForProofObject[i].getFirstLayer().getAesEncryptionInformationSegment();
            AESEncryptionInformationSegmentAttestation aesEncryptionInformationSegment =
                    encryptedAESEncryptionInformationSegment.decrypt(privateEntityIdentifiersReceivers[i], attestationPolicies[i]);
            var aesKeys = aesEncryptionInformationSegment.getAesKeyInformation();

            storageElementIdentifiersForProofObject[i] = attestationsForProofObject[i].getStorageLayerIdentifier();
            firstAESKeysForProofObject[i] = aesKeys.getLeft();
            secondAESKeysForProofObject[i] = aesKeys.getRight();
        }
        var proof = new ProofObject(Arrays.copyOfRange(storageElementIdentifiersForProofObject, 0, storageElementIdentifiersForProofObject.length - 1),
                Arrays.copyOfRange(firstAESKeysForProofObject, 0, storageElementIdentifiersForProofObject.length - 1),
                firstAESKeysForProofObject[3]);
        System.out.println(String.format("Proof object manually generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));


        // 10) Generate the proof automatically.
        counter = System.currentTimeMillis();
        RTreePolicy policyToProve = new RTreePolicy(PolicyRight.READ, "A", "B", "C");
        var automaticallyConstructedProof = ProofObject.generateProofObject(delegateAttestation, firstAESKeysForProofObject[2],
                secondAESKeysForProofObject[2], firstAESKeysForProofObject[3], storageLayerUserC);
        System.out.println(String.format("Proof object automatically generated (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));
        assertEquals(proof, automaticallyConstructedProof);

        // 11) Verify the proof object.
        counter = System.currentTimeMillis();
        var provenPolicy = proof.verify(storageLayerUserA);
        System.out.println(String.format("Proof object verified (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));
        assertEquals(policyToProve, provenPolicy);

        // 12) Revoke the share Attestation.
        counter = System.currentTimeMillis();
        userAShareAttestationRevocationSecret.revealInStorageLayer(storageLayerUserA);
        System.out.println(String.format("One revocation secret revealed (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));

        // 13) Check if the proof object can still be verified.
        counter = System.currentTimeMillis();
        assertThrows(IllegalArgumentException.class, () -> proof.verify(storageLayerUserA));
        System.out.println(String.format("Invalid proof object successfully detected (time needed: %s milliseconds).",
                System.currentTimeMillis() - counter));
    }
}