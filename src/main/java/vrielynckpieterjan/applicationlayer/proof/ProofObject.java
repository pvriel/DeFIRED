package vrielynckpieterjan.applicationlayer.proof;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.applicationlayer.attestation.NamespaceAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.VerificationInformationSegmentAttestation;
import vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.IOException;
import java.io.Serializable;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Class representing a proof object.
 */
public class ProofObject implements Serializable {

    private final static Logger logger = Logger.getLogger(ProofObject.class.getName());

    private final StorageElementIdentifier[] storageElementIdentifiers;
    private final String[] aesKeys;

    public ProofObject(StorageElementIdentifier[] storageElementIdentifiers,
                       String[] aesKeys) throws IllegalArgumentException {
        if (storageElementIdentifiers.length == 0) throw new IllegalArgumentException("Not enough StorageElementIdentifiers provided.");
        if (aesKeys.length == 0) throw new IllegalArgumentException("Not enough AES keys provided.");
        if (storageElementIdentifiers.length != aesKeys.length) throw new IllegalArgumentException(String.format("" +
                "An equal amount of StorageElementIdentifiers (total: %s) and AES keys (total: %s) should be provided.",
                storageElementIdentifiers.length, aesKeys.length));

        this.storageElementIdentifiers = storageElementIdentifiers;
        this.aesKeys = aesKeys;
    }

    public @NotNull RTreePolicy getProvedPolicy(@NotNull StorageLayer storageLayer) throws IOException, IllegalArgumentException {
        logger.info(String.format("Trying to verify ProofObject (%s)...", this));
        RTreePolicy policyLastCheckedAttestation = null;

        for (int i = 0; i < storageElementIdentifiers.length; i ++) {
            Set<StorageElement> retrievedStorageElements = storageLayer.retrieve(storageElementIdentifiers[i]);

            boolean compatibleAttestationFound = false;
            for (StorageElement retrievedStorageElement : retrievedStorageElements) {
                if (!(retrievedStorageElement instanceof Attestation)) continue;
                if (i == 0 && !(retrievedStorageElement instanceof NamespaceAttestation)) continue;
                IssuerPartAttestation issuerPartAttestation = ((Attestation) retrievedStorageElement).getFirstLayer();
                AESCipherEncryptedSegment<VerificationInformationSegmentAttestation> encryptedVerificationInformationSegment =
                        issuerPartAttestation.getVerificationInformationSegment();

                try {
                    VerificationInformationSegmentAttestation verificationInformationSegment =
                            encryptedVerificationInformationSegment.decrypt(aesKeys[i]);
                    RTreePolicy foundPolicy = verificationInformationSegment.getRTreePolicy();
                    if (policyLastCheckedAttestation == null || policyLastCheckedAttestation.coversRTreePolicy(foundPolicy)) {
                        compatibleAttestationFound = true;
                        policyLastCheckedAttestation = foundPolicy;
                        logger.info(String.format("Found a valid Attestation for the %sth StorageElementIdentifier for ProofObject (%s);" +
                                " current RTree policy: %s", i, this, foundPolicy.toString()));
                        break;
                    }
                } catch (IllegalArgumentException ignored) {}
            }

            if (!compatibleAttestationFound) {
                logger.warning(String.format("ProofObject (%s) could not be verified (reason: no " +
                        "compatible Attestation found for the %sth StorageElementIdentifier.", this, i));
                throw new IllegalArgumentException(String.format(
                        "No compatible Attestation found for the %sth StorageElementIdentifier.", i));
            }
        }

        logger.info(String.format("ProofObject (%s) verified; resulting RTree policy: %s", this, policyLastCheckedAttestation));
        return policyLastCheckedAttestation;
    }

}
