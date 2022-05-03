package vrielynckpieterjan.masterproef;

import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroon;
import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroonManager;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.proof.ProofObject;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;

import java.io.FileWriter;
import java.io.IOException;

public class ThesisStudentDemo {

    public static void main(String[] args) throws IOException {
        FileWriter fileWriter;

        System.out.println("Invitations...");
        fileWriter = new FileWriter("invitation_objects.txt");
        for (int i = 8; i <= 100; i ++) {
            RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.READ, "A".repeat(i - 7));
            var entityPair = EntityIdentifier.generateEntityIdentifierPair("");
            IssuerPartAttestation issuerPartAttestation = new IssuerPartAttestation(entityPair.getKey(), entityPair.getValue(),
                    entityPair.getRight(), new RevocationCommitment(), rTreePolicy);
            byte[] serialized = ExportableUtils.serialize(issuerPartAttestation);
            fileWriter.write(String.format("%s\t%s%n", i, serialized.length));
        }
        fileWriter.close();

        System.out.println("Attestations...");
        fileWriter = new FileWriter("attestation_objects.txt");
        for (int i = 8; i <= 100; i ++) {
            RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.READ, "A".repeat(i - 7));
            var entityPair = EntityIdentifier.generateEntityIdentifierPair("");
            IssuerPartAttestation issuerPartAttestation = new IssuerPartAttestation(entityPair.getKey(), entityPair.getValue(),
                    entityPair.getRight(), new RevocationCommitment(), rTreePolicy);
            Attestation attestation = new Attestation(new StorageElementIdentifier(), issuerPartAttestation, new RevocationCommitment(),
                    new StorageElementIdentifier(), entityPair.getKey());
            byte[] serialized = ExportableUtils.serialize(attestation);
            fileWriter.write(String.format("%s\t%s%n", i, serialized.length));
        }
        fileWriter.close();

        System.out.println("Proof objects...");
        fileWriter = new FileWriter("proof_objects.txt");
        for (int i = 1; i <= 1000; i ++) {
            String[] aesKeys = new String[i];
            StorageElementIdentifier[] storageElementIdentifiers = new StorageElementIdentifier[i];
            for (int j = 0; j < i; j ++) {
                aesKeys[j] = AESCipherEncryptedSegment.generateAESKey();
                storageElementIdentifiers[j] = new StorageElementIdentifier();
            }
            ProofObject proofObject = new ProofObject(storageElementIdentifiers, aesKeys, "");
            byte[] serialized = ExportableUtils.serialize(proofObject);
            fileWriter.write(String.format("%s\t%s%n", i, serialized.length));
        }
        fileWriter.close();

        System.out.println("Macaroon objects...");
        APILayerMacaroonManager apiLayerMacaroonManager = new APILayerMacaroonManager();
        fileWriter = new FileWriter("macaroon_objects.txt");
        for (int i = 8; i <= 1000; i ++) {
            RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.READ, "A".repeat(i - 7));
            APILayerMacaroon macaroon = apiLayerMacaroonManager.registerPolicy(rTreePolicy);
            byte[] serialized = ExportableUtils.serialize(macaroon);
            fileWriter.write(String.format("%s\t%s%n", i, serialized.length));
        }
        fileWriter.close();


        System.out.println("Done.");
    }
}
