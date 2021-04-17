package vrielynckpieterjan.masterproef.storagelayer;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.map.HashMapStorageLayer;

import javax.swing.text.html.parser.Entity;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class StorageLayerTest {

    StorageLayer storageLayer;

    @BeforeEach
    void setUp() {
        storageLayer = new HashMapStorageLayer();
    }

    @Test
    void retrieve() throws IOException {
        var storageElementIdentifier = new StorageElementIdentifier();
        var storageElement = new TestStorageElement(storageElementIdentifier);
        storageLayer.put(storageElement);

        var retrieved = storageLayer.retrieve(storageElementIdentifier);
        assertEquals(1, retrieved.size());
        retrieved.forEach(storageElement1 ->
                assertEquals(storageElementIdentifier, storageElement1.getStorageLayerIdentifier()));
        retrieved.clear();

        retrieved.addAll(storageLayer.retrieve(storageElementIdentifier, Attestation.class));
        assertEquals(0, retrieved.size());
    }

    @Test
    void getPersonalQueueUser() throws IOException {
        var cloudService = EntityIdentifier.generateEntityIdentifierPair("test");
        var user = EntityIdentifier.generateEntityIdentifierPair("test");

        var storageLayerIdentifierOne = new StorageElementIdentifier(user.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
        var storageLayerIdentifierTwo = new StorageElementIdentifier("A second identifier");

        var issuerPartAttestationOne = new IssuerPartAttestation(cloudService.getLeft(), cloudService.getRight(),
                user.getRight(), new RevocationCommitment(""), new RTreePolicy(PolicyRight.WRITE, "A"));
        var attestationOne = new Attestation(storageLayerIdentifierOne, issuerPartAttestationOne,
                new RevocationCommitment(""), storageLayerIdentifierTwo, user.getLeft());
        var issuerPartAttestationTwo = new IssuerPartAttestation(cloudService.getLeft(), cloudService.getRight(),
                user.getRight(), new RevocationCommitment(""), new RTreePolicy(PolicyRight.WRITE, "A"));
        var attestationTwo = new Attestation(storageLayerIdentifierTwo, issuerPartAttestationTwo,
                new RevocationCommitment(""), storageLayerIdentifierOne, user.getLeft());

        storageLayer.put(attestationOne);
        storageLayer.put(attestationTwo);

        var personalQueueIterator = storageLayer.getPersonalQueueUser(user.getRight());
        var foundAttestation = personalQueueIterator.next();
        assertEquals(storageLayerIdentifierOne, foundAttestation.getStorageLayerIdentifier());
        foundAttestation = personalQueueIterator.next();
        assertEquals(storageLayerIdentifierTwo, foundAttestation.getStorageLayerIdentifier());
        foundAttestation = personalQueueIterator.next();
        assertEquals(storageLayerIdentifierOne, foundAttestation.getStorageLayerIdentifier());
    }

    public static class TestStorageElement extends StorageElement {

        /**
         * Constructor for the {@link StorageElement} class.
         *
         * @param identifier The {@link StorageElementIdentifier} for this {@link StorageElement}.
         */
        public TestStorageElement(@NotNull StorageElementIdentifier identifier) {
            super(identifier);
        }
    }
}