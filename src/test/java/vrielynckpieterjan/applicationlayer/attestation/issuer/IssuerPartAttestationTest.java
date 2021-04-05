package vrielynckpieterjan.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;

import static org.junit.jupiter.api.Assertions.*;

class IssuerPartAttestationTest {

    Pair<PrivateEntityIdentifier, PublicEntityIdentifier> issuerIdentifiers = EntityIdentifier.generateEntityIdentifierPair("");
    Pair<PrivateEntityIdentifier, PublicEntityIdentifier> receiverIdentifiers = EntityIdentifier.generateEntityIdentifierPair("");
    String ibeIdentifierAESEncryptionInformation = "test";
    RevocationCommitment revocationCommitment = new RevocationCommitment(new RevocationSecret());
    RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.WRITE, "A", "B", "C");
    IssuerPartAttestation issuerPartAttestation = new IssuerPartAttestation(issuerIdentifiers.getLeft(),
            issuerIdentifiers.getRight(), receiverIdentifiers.getRight(),
            revocationCommitment, rTreePolicy);

    @Test
    void hasValidSignature() {
        assertTrue(issuerPartAttestation.hasValidSignature(receiverIdentifiers.getLeft(), issuerIdentifiers.getRight()));

        /*
        Why the following part of this test:
        In Java: serializing & deserializing an object ==> different memory allocation, which means the hashes
        of the objects may be different if the IssuerPartAttestation class is incorrectly implemented.

        P.S.: Yes it took me a lot of time to fix this...
         */
        byte[] serializedIssuerPartAttestation = SerializationUtils.serialize(issuerPartAttestation);
        IssuerPartAttestation deserializedIssuerPartAttestation = SerializationUtils.deserialize(serializedIssuerPartAttestation);
        assertTrue(deserializedIssuerPartAttestation.hasValidSignature(receiverIdentifiers.getLeft(), issuerIdentifiers.getRight()));
    }
}