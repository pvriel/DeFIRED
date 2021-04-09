package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class SimpleAPILayerServer extends TCPReflectionMethodInvocationServer {

    private final static Logger logger = Logger.getLogger(SimpleAPILayerServer.class.getName());

    private final StorageLayer storageLayer;
    private final Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers;
    private final Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies;
    private final Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers;

    public SimpleAPILayerServer(int amountOfThreads, int port, @NotNull StorageLayer storageLayer,
                                @NotNull Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers,
                                @NotNull Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies,
                                @NotNull Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers) throws IOException {
        super(amountOfThreads, port);
        this.storageLayer = storageLayer;
        this.registeredUsers = registeredUsers;
        this.revocationSecretsAcceptedPolicies = revocationSecretsAcceptedPolicies;
        this.currentStorageElementIdentifiers = currentStorageElementIdentifiers;
    }

    public @NotNull ReflectionMethodInvocationServerResponse receiveIssuerPartAttestation (
            @NotNull IssuerPartAttestation issuerPartAttestation,
            @NotNull String firstAESKey) {
        // TODO: register this attestation.
        try {
            // 1) Verify the issuer's part.
            // 1.1) Verify the public identity identifier.
            if (!registeredUsers.containsKey(issuerPartAttestation.getPublicEntityIdentifierReceiver()))
                throw new IllegalArgumentException("Unknown receiver.");
            // 1.2) Verify the authenticity of the first layer.
            var verificationInformation = issuerPartAttestation.getVerificationInformationSegment()
                    .decrypt(firstAESKey);
            var ephemeralPrivateRSAKey = verificationInformation.getEncryptedEmpiricalPrivateRSAKey()
                    .decrypt(verificationInformation.getPublicEntityIdentifierIssuer());
            var ephemeralPublicRSAKey = issuerPartAttestation.getEmpiricalPublicKey();
            if (!issuerPartAttestation.hasValidSignature(ephemeralPrivateRSAKey, ephemeralPublicRSAKey))
                throw new IllegalArgumentException("Invalid first layer provided.");

            // 2) Generate the full attestation & register the revocation commitment.
            var oldStorageElementIdentifier = currentStorageElementIdentifiers.get(
                    issuerPartAttestation.getPublicEntityIdentifierReceiver());
            var newStorageElementIdentifier = new StorageElementIdentifier();
            currentStorageElementIdentifiers.put(issuerPartAttestation.getPublicEntityIdentifierReceiver(), newStorageElementIdentifier);

            var revocationSecret = new RevocationSecret();
            var revocationCommitment = new RevocationCommitment(revocationSecret);
            var acceptedPolicy = verificationInformation.getRTreePolicy();
            if (!revocationSecretsAcceptedPolicies.containsKey(issuerPartAttestation.getPublicEntityIdentifierReceiver()))
                revocationSecretsAcceptedPolicies.put(issuerPartAttestation.getPublicEntityIdentifierReceiver(),
                        Collections.synchronizedMap(new HashMap<>()));
            revocationSecretsAcceptedPolicies.get(issuerPartAttestation.getPublicEntityIdentifierReceiver())
                    .put(acceptedPolicy, revocationSecret);

            var attestation = new Attestation(oldStorageElementIdentifier, issuerPartAttestation,
                    revocationCommitment, newStorageElementIdentifier, registeredUsers.get(issuerPartAttestation.getPublicEntityIdentifierReceiver()));

            // 3) Publish the attestation.
            storageLayer.put(attestation);
            logger.info(String.format("SimpleAPILayerServer (%s) registered a new Attestation for " +
                    "user (%s) for policy (%s).", this, issuerPartAttestation.getPublicEntityIdentifierReceiver(), acceptedPolicy));
            return new ReflectionMethodInvocationServerResponse("OK");

        } catch (IllegalArgumentException | IOException e) {
            return new ReflectionMethodInvocationServerResponse(e);
        }
    }
}
