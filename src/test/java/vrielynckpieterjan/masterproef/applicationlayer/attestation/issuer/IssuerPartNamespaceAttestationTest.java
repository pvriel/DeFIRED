package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;

import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.assertTrue;

class IssuerPartNamespaceAttestationTest {

    Pair<PrivateEntityIdentifier, PublicEntityIdentifier> issuerIdentifiers = EntityIdentifier.generateEntityIdentifierPair("");
    Pair<PrivateEntityIdentifier, PublicEntityIdentifier> receiverIdentifiers = EntityIdentifier.generateEntityIdentifierPair("");
    String ibeIdentifierAESEncryptionInformation = "test";
    RevocationCommitment revocationCommitment = new RevocationCommitment(new RevocationSecret());
    RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.WRITE, "A", "B", "C");
    InetSocketAddress referenceAPILayer = new InetSocketAddress("localhost", 5678);
    IssuerPartNamespaceAttestation issuerPartAttestation = new IssuerPartNamespaceAttestation(issuerIdentifiers.getLeft(),
            issuerIdentifiers.getRight(), receiverIdentifiers.getRight(),
            revocationCommitment, rTreePolicy, referenceAPILayer);

    @Test
    void hasValidSignature() {
        assertTrue(issuerPartAttestation.hasValidSignature(receiverIdentifiers.getLeft(), issuerIdentifiers.getRight(),
                rTreePolicy));

        /*
        Why the following part of this test:
        In Java: serializing & deserializing an object ==> different memory allocation, which means the hashes
        of the objects may be different if the IssuerPartAttestation class is incorrectly implemented.

        P.S.: Yes it took me a lot of time to fix this...
         */
        byte[] serializedIssuerPartAttestation = SerializationUtils.serialize(issuerPartAttestation);
        IssuerPartAttestation deserializedIssuerPartAttestation = SerializationUtils.deserialize(serializedIssuerPartAttestation);
        assertTrue(deserializedIssuerPartAttestation.hasValidSignature(receiverIdentifiers.getLeft(), issuerIdentifiers.getRight(),
                rTreePolicy));
    }
}