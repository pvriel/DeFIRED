package vrielynckpieterjan.masterproef.applicationlayer.proof;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;
import vrielynckpieterjan.masterproef.storagelayer.map.MultiMappedStorageLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DisproofObjectTest {

    @Test
    void verify() throws IOException {
        Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userA = EntityIdentifier.generateEntityIdentifierPair("");
        Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userB = EntityIdentifier.generateEntityIdentifierPair("");

        RevocationCommitment revocationCommitment = new RevocationCommitment(); // Not important here.
        RTreePolicy rTreePolicyNamespaceAttestationUserA = new RTreePolicy(PolicyRight.WRITE, "A");
        RTreePolicy rTreePolicyNamespaceAttestationUserB = new RTreePolicy(PolicyRight.WRITE, "B");
        StorageElementIdentifier storageElementIdentifierNextElementPersonalQueueUserA = new StorageElementIdentifier();
        StorageElementIdentifier storageElementIdentifierNextElementPersonalQueueUserB = new StorageElementIdentifier();
        IssuerPartNamespaceAttestation issuerPartNamespaceAttestationUserA = new IssuerPartNamespaceAttestation(userA.getLeft(),
                userA.getRight(), userA.getRight(), revocationCommitment, rTreePolicyNamespaceAttestationUserA, new InetSocketAddress("localhost", 0)); // Must arguments are not important here.
        IssuerPartNamespaceAttestation issuerPartNamespaceAttestationUserB = new IssuerPartNamespaceAttestation(userB.getLeft(),
                userB.getRight(), userB.getRight(), revocationCommitment, rTreePolicyNamespaceAttestationUserB, new InetSocketAddress("localhost", 0));
        NamespaceAttestation namespaceAttestationUserA = new NamespaceAttestation(issuerPartNamespaceAttestationUserA,
                revocationCommitment, storageElementIdentifierNextElementPersonalQueueUserA, userA.getRight(), userA.getLeft());
        NamespaceAttestation namespaceAttestationUserB = new NamespaceAttestation(issuerPartNamespaceAttestationUserB,
                revocationCommitment, storageElementIdentifierNextElementPersonalQueueUserB, userB.getRight(), userB.getLeft());

        StorageLayer storageLayer = new MultiMappedStorageLayer();
        storageLayer.put(namespaceAttestationUserA);
        storageLayer.put(namespaceAttestationUserB);

        RTreePolicy policyToDisprove = new RTreePolicy(PolicyRight.READ, "B", "A");
        DisproofObject disproofObject = new DisproofObject(userA.getRight(), userA.getLeft(), policyToDisprove);
        disproofObject.verify(storageLayer);

        IssuerPartAttestation issuerPartAttestationThatRuinsEverything = new IssuerPartAttestation(userB.getLeft(),
                userB.getRight(), userA.getRight(), revocationCommitment, new RTreePolicy(PolicyRight.WRITE, "B", "A"));
        Attestation attestationThatRuinsEverything = new Attestation(storageElementIdentifierNextElementPersonalQueueUserA,
                issuerPartAttestationThatRuinsEverything, revocationCommitment, storageElementIdentifierNextElementPersonalQueueUserA,
                userA.getLeft());
        storageLayer.put(attestationThatRuinsEverything);
        assertThrows(IllegalStateException.class, () -> disproofObject.verify(storageLayer));
    }
}