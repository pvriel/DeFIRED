package vrielynckpieterjan.masterproef.apilayer.server;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.apilayer.server.fileserver.FileServerInterface;
import vrielynckpieterjan.masterproef.apilayer.server.fileserver.FileServerRequest;
import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroon;
import vrielynckpieterjan.masterproef.apilayer.macaroon.APILayerMacaroonManager;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.applicationlayer.proof.ProofObject;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

import java.io.IOException;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Class representing the external server part of the {@link vrielynckpieterjan.masterproef.apilayer.APILayer} class.
 * This class represents the {@link ReflectionMethodInvocationServer} instance for an {@link vrielynckpieterjan.masterproef.apilayer.APILayer}
 * instance, which contains the {@link java.lang.reflect.Method}s which may be invoked externally.
 */
public class SimpleAPILayerServer extends TCPReflectionMethodInvocationServer {

    private final static Logger logger = Logger.getLogger(SimpleAPILayerServer.class.getName());

    private final StorageLayer storageLayer;
    private final Map<PublicEntityIdentifier, PrivateEntityIdentifier> registeredUsers;
    private final Map<PublicEntityIdentifier, Map<RTreePolicy, RevocationSecret>> revocationSecretsAcceptedPolicies;
    private final Map<PublicEntityIdentifier, StorageElementIdentifier> currentStorageElementIdentifiers;
    private final APILayerMacaroonManager apiLayerMacaroonManager = new APILayerMacaroonManager();
    private final FileServerInterface fileServer;

    /**
     * Constructor for the {@link SimpleAPILayerServer} class.
     * @param   amountOfThreads
     *          The amount of simultaneous requests the {@link SimpleAPILayerServer} can support.
     * @param   port
     *          The port on which the {@link SimpleAPILayerServer} should run.
     * @param   storageLayer
     *          The {@link StorageLayer}.
     * @param   registeredUsers
     *          A {@link Map}, linking the {@link PublicEntityIdentifier}s of the registered users of the cloud
     *          storage service provider to their {@link PrivateEntityIdentifier} counterparts.
     * @param   revocationSecretsAcceptedPolicies
     *          A {@link Map}, linking the {@link PublicEntityIdentifier}s of the registered users of the cloud
     *          storage service provider to another {@link Map}. The latter one maps the {@link RTreePolicy}s
     *          of the accepted {@link IssuerPartAttestation}s for that user to the included {@link RevocationSecret}
     *          (as a {@link RevocationCommitment}) of the same user.
     * @param   currentStorageElementIdentifiers
     *          A {@link Map}, mapping the {@link PublicEntityIdentifier}s of the registered users of the cloud
     *          storage service provider to the {@link StorageElementIdentifier} for the next element in the personal
     *          queue of that user.
     * @param   fileServer
     *          The {@link FileServerInterface} realization for this {@link SimpleAPILayerServer}.
     * @throws  IOException
     *          If an IO-related exception occurred while booting the server.
     */
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

    /**
     * Method to complete a received {@link IssuerPartAttestation} and store the result in the {@link StorageLayer}.
     * This method however returns a {@link ReflectionMethodInvocationServerResponse} with an Exception
     * if the authenticity of the first layer could not be verified, or if the {@link PublicEntityIdentifier}
     * mentioned in the plaintext header of the provided {@link IssuerPartAttestation} can not be linked
     * to a registered user of the cloud storage service provider.
     * @param   issuerPartAttestation
     *          The received {@link IssuerPartAttestation} instance.
     * @param   firstAESKey
     *          The first ephemeral AES key of the {@link IssuerPartAttestation} instance to verify its
     *          authenticity with.
     * @return  A new {@link ReflectionMethodInvocationServerResponse} with the String "OK" if the operation
     *          succeeded, or with an Exception if the operation failed due to a previously mentioned problem.
     */
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
            var ephemeralPrivateECKey = verificationInformation.getEncryptedEmpiricalPrivateECKey()
                    .decrypt(verificationInformation.getPublicEntityIdentifierIssuer());
            var ephemeralPublicECKey = issuerPartAttestation.getEmpiricalPublicKey();
            if (!issuerPartAttestation.hasValidSignature(ephemeralPrivateECKey, ephemeralPublicECKey))
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

    /**
     * Method to receive a valid {@link ProofObject} and convert it to a valid {@link APILayerMacaroon}.
     * @param   proofObject
     *          The {@link ProofObject}.
     * @return  A {@link ReflectionMethodInvocationServerResponse} containing the generated {@link APILayerMacaroon}
     *          if the provided {@link ProofObject} is valid, or a {@link ReflectionMethodInvocationServerResponse}
     *          containing an Exception if the provided {@link ProofObject} is invalid.
     */
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

    /**
     * Method to invoke a {@link FileServerInterface} method of the {@link vrielynckpieterjan.masterproef.apilayer.APILayer}.
     * @param   macaroon
     *          A {@link APILayerMacaroon}, which proves that the user is allowed to invoke the specified {@link FileServerInterface}
     *          operation specified by the provided {@link FileServerRequest} instance.
     * @param   fileServerRequest
     *          The {@link FileServerRequest} instance, specifying the method the user wants to invoke.
     * @return  A {@link ReflectionMethodInvocationServerResponse} instance which either contains the result of the operation,
     *          or which contains an Exception if the operation could not be executed due to an invalid {@link APILayerMacaroon}.
     */
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
