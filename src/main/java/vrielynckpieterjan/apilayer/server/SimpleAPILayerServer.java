package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.apilayer.fileserver.FileServerInterface;
import vrielynckpieterjan.apilayer.fileserver.FileServerRequest;
import vrielynckpieterjan.apilayer.macaroon.APILayerMacaroon;
import vrielynckpieterjan.apilayer.macaroon.APILayerMacaroonManager;
import vrielynckpieterjan.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.applicationlayer.proof.ProofObject;
import vrielynckpieterjan.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
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
    private final APILayerMacaroonManager apiLayerMacaroonManager = new APILayerMacaroonManager();
    private final FileServerInterface fileServer;

    public SimpleAPILayerServer(int amountOfThreads, int port, @NotNull StorageLayer storageLayer,
                                @NotNull Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers,
                                @NotNull Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies,
                                @NotNull Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers,
                                @NotNull FileServerInterface fileServer) throws IOException {
        super(amountOfThreads, port);
        this.storageLayer = storageLayer;
        this.registeredUsers = registeredUsers;
        this.revocationSecretsAcceptedPolicies = revocationSecretsAcceptedPolicies;
        this.currentStorageElementIdentifiers = currentStorageElementIdentifiers;
        this.fileServer = fileServer;
    }

    public @NotNull ReflectionMethodInvocationServerResponse receiveIssuerPartAttestation(
            @NotNull IssuerPartAttestation issuerPartAttestation,
            @NotNull String firstAESKey) {
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

        } catch (Exception e) {
            return new ReflectionMethodInvocationServerResponse(e);
        }
    }

    public @NotNull ReflectionMethodInvocationServerResponse receiveProofObject
            (@NotNull ProofObject proofObject) {
        try {
            // 1) Verify the proof object.
            var policy = proofObject.verify(storageLayer);
            // TODO: check if the policy connects to a registered user.
            var macaroon = apiLayerMacaroonManager.registerPolicy(policy);
            return new ReflectionMethodInvocationServerResponse(macaroon);
        } catch (Exception e) {
            return new ReflectionMethodInvocationServerResponse(e);
        }
    }

    public @NotNull ReflectionMethodInvocationServerResponse handleFileServerRequest
            (@NotNull APILayerMacaroon macaroon,
             @NotNull FileServerRequest fileServerRequest) {
        RTreePolicy policy;
        try {
            policy = apiLayerMacaroonManager.returnVerifiedPolicy(macaroon);
        } catch (IllegalArgumentException e) {
            return new ReflectionMethodInvocationServerResponse(e);
        }

        if (!fileServerRequest.coveredByPolicy(policy))
            return new ReflectionMethodInvocationServerResponse(new IllegalArgumentException("The provided" +
                    " macaroon does not cover the specified resources for the specified access rights."));

        try {
            var method = fileServer.getClass().getMethod(fileServerRequest.getFileServerInterfaceMethodName(),
                    fileServerRequest.getClass());
            var result = method.invoke(fileServer, fileServerRequest);
            if (result instanceof Serializable)
                return new ReflectionMethodInvocationServerResponse((Serializable) result);
            else return new ReflectionMethodInvocationServerResponse(true);
        } catch (NoSuchMethodException e) {
            return new ReflectionMethodInvocationServerResponse(new IllegalArgumentException("File server operation unknown."));
        } catch (Exception e) {
            return new ReflectionMethodInvocationServerResponse(new IllegalArgumentException(
                    String.format("Could not invoke the file server operation (reason: %s).", e)));
        }
    }

}
