package vrielynckpieterjan.masterproef;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartNamespaceAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.proof.ProofObject;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.map.HashMapStorageLayer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Demo {

    private final static String GREEN = "\u001B[32m";
    private final static String BLUE = "\u001B[34m";
    private final static String RESET = "\u001B[0m";

    public static void main(String[] args) throws IOException {
        // Generating the storage layer.
        var storageLayer = new HashMapStorageLayer();

        // Generating encryption keys for the cloud storage service providers.
        var cloudA = EntityIdentifier.generateEntityIdentifierPair("cloudA");
        var cloudB = EntityIdentifier.generateEntityIdentifierPair("cloudB");
        var cloudC = EntityIdentifier.generateEntityIdentifierPair("cloudC");
        List<Pair<String, Pair<PrivateEntityIdentifier, PublicEntityIdentifier>>> clouds = new ArrayList<>();
        clouds.add(new ImmutablePair<>("cloudA", cloudA));
        clouds.add(new ImmutablePair<>("cloudB", cloudB));
        clouds.add(new ImmutablePair<>("cloudC", cloudC));

        // Generating encryption keys for the users.
        var userA = EntityIdentifier.generateEntityIdentifierPair("userA");
        var userB = EntityIdentifier.generateEntityIdentifierPair("userB");
        var userC = EntityIdentifier.generateEntityIdentifierPair("userC");
        List<Pair<String, Pair<PrivateEntityIdentifier, PublicEntityIdentifier>>> users = new ArrayList<>();
        users.add(new ImmutablePair<>("userA", userA));
        users.add(new ImmutablePair<>("userB", userB));
        users.add(new ImmutablePair<>("userC", userC));

        List<Pair<String, Pair<PrivateEntityIdentifier, PublicEntityIdentifier>>> allEntities = new ArrayList<>();
        allEntities.addAll(clouds);
        allEntities.addAll(users);
        for (var entity: allEntities) {
            System.out.printf("%s%s%s%n%sPublic RSA key:%s\t%s%n%sPrivate RSA key:%s\t%s%n%sIBE parameters:%s\t%s%n%sStorage layer identifier namespace attestation:%s\t%s%n%n",
                    BLUE, entity.getLeft(), RESET,
                    GREEN, RESET, entity.getRight().getLeft().getRSAIdentifier(),
                    GREEN, RESET, entity.getRight().getRight().getRSAIdentifier(),
                    GREEN, RESET, entity.getRight().getLeft().getIBEIdentifier(),
                    GREEN, RESET, entity.getRight().getRight().getNamespaceServiceProviderEmailAddressUserConcatenation());
        }

        Map<PublicEntityIdentifier, StorageElementIdentifier> queueStorageElementIdentifiers = new HashMap<>();
        queueStorageElementIdentifiers.put(userA.getRight(), new StorageElementIdentifier(userA.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation()));
        queueStorageElementIdentifiers.put(userB.getRight(), new StorageElementIdentifier(userB.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation()));
        queueStorageElementIdentifiers.put(userC.getRight(), new StorageElementIdentifier(userC.getRight().getNamespaceServiceProviderEmailAddressUserConcatenation()));

        // Registering the users to the respective cloud storage service providers.
        NamespaceAttestation namespaceAttestationUserC = null;
        for (var i = 0; i < 3; i ++) {
            var user = users.get(i);
            var cloud = clouds.get(i);
            var issuerPartNamespaceAttestation = new IssuerPartNamespaceAttestation(
                    cloud.getRight().getLeft(), cloud.getRight().getRight(), user.getRight().getRight(), new RevocationCommitment(new RevocationSecret()),
                    new RTreePolicy(PolicyRight.WRITE, user.getLeft()), new InetSocketAddress("localhost", 8000));
            var newNextStorageElementIdentifierPersonalQueue = new StorageElementIdentifier();
            queueStorageElementIdentifiers.put(user.getRight().getRight(), newNextStorageElementIdentifierPersonalQueue);
            var namespaceAttestation = new NamespaceAttestation(issuerPartNamespaceAttestation,
                    new RevocationCommitment(new RevocationSecret()), newNextStorageElementIdentifierPersonalQueue,
                    user.getRight().getRight(), user.getRight().getLeft());
            storageLayer.put(namespaceAttestation);
            if (i == 2) namespaceAttestationUserC = namespaceAttestation;
            System.out.printf("%sNamespace attestation %s:%s\t%s%n", BLUE, user.getLeft(), RESET, namespaceAttestation);
        }
        System.out.println();

        // Generating the necessary attestations for the demo.
        var policy = new RTreePolicy(PolicyRight.WRITE, "userA", "file");
        List<Pair<Pair<PrivateEntityIdentifier, PublicEntityIdentifier>, Pair<PrivateEntityIdentifier, PublicEntityIdentifier>>>
                issuersReceiversAttestationsDemo = new ArrayList<>();
        issuersReceiversAttestationsDemo.add(new ImmutablePair<>(userA, userB));
        issuersReceiversAttestationsDemo.add(new ImmutablePair<>(userA, userC));
        issuersReceiversAttestationsDemo.add(new ImmutablePair<>(userB, userC));
        List<String> entityNames = new ArrayList<>(Arrays.asList("userA", "userB", "userA", "userC", "userB", "userC"));
        List<Attestation> generatedAttestationsForDemo = new ArrayList<>();
        for (var issuerReceiverCombination: issuersReceiversAttestationsDemo) {
            var issuer = issuerReceiverCombination.getLeft();
            var receiver = issuerReceiverCombination.getRight();
            var issuerPartAttestation = new IssuerPartAttestation(issuer.getLeft(), issuer.getRight(),
                    receiver.getRight(), new RevocationCommitment(new RevocationSecret()), policy);
            var newNextStorageElementIdentifierPersonalQueue = new StorageElementIdentifier();
            var oldNextStorageLayerIdentifier = queueStorageElementIdentifiers.get(receiver.getRight());
            queueStorageElementIdentifiers.put(receiver.getRight(), newNextStorageElementIdentifierPersonalQueue);
            var attestation = new Attestation(oldNextStorageLayerIdentifier, issuerPartAttestation,
                    new RevocationCommitment(new RevocationSecret()),
                    newNextStorageElementIdentifierPersonalQueue, receiver.getLeft());
            storageLayer.put(attestation);
            generatedAttestationsForDemo.add(attestation);
            System.out.printf("%sAttestation (%s --> %s):%s\t%s%n", BLUE, entityNames.remove(0), entityNames.remove(0), RESET, attestation);
        }

        // Obtain the first ephemeral AES key of the namespace attestation of user C.
        var aesEncryptionInformationSegmentNamespaceAttestationUserC =
                namespaceAttestationUserC.getFirstLayer().getAesEncryptionInformationSegment();
        var aesKeys = aesEncryptionInformationSegmentNamespaceAttestationUserC.decrypt(userC.getLeft(), new RTreePolicy(PolicyRight.WRITE, "userC"));
        var firstEphemeralAESKeyNamespaceAttestationUserC = aesKeys.getAesKeyInformation().getLeft();
        aesKeys = generatedAttestationsForDemo.get(2).getFirstLayer().getAesEncryptionInformationSegment()
                .decrypt(userC.getLeft(), policy);
        Logger.getLogger(ProofObject.class.getName()).setLevel(Level.ALL);
        ProofObject.generateProofObject(generatedAttestationsForDemo.get(2), aesKeys.getAesKeyInformation().getLeft(),
                aesKeys.getAesKeyInformation().getRight(), firstEphemeralAESKeyNamespaceAttestationUserC, storageLayer);
    }
}
