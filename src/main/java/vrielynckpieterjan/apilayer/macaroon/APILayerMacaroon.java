package vrielynckpieterjan.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;

import java.io.Serializable;

/**
 * Class representing a macaroon object for the API layer.
 */
public class APILayerMacaroon implements Serializable {

    private final PublicIdentifierMacaroonElement publicIdentifier;
    private final RTreePolicyMacaroonElement rTreePolicyMacaroonElement;

    /**
     * Constructor for the {@link APILayerMacaroon} class.
     * @param   macaroonSecret
     *          The macaroon secret.
     * @param   macaroonPublicIdentifier
     *          The public identifier of the macaroon.
     * @param   rTreePolicy
     *          The encapsulated {@link RTreePolicy}.
     */
    public APILayerMacaroon(@NotNull String macaroonSecret,
                            @NotNull String macaroonPublicIdentifier,
                            @NotNull RTreePolicy rTreePolicy) {
        publicIdentifier = new PublicIdentifierMacaroonElement(macaroonSecret, macaroonPublicIdentifier);
        rTreePolicyMacaroonElement = new RTreePolicyMacaroonElement(publicIdentifier, rTreePolicy);
    }

    /**
     * Getter for the public identifier of the macaroon.
     * @return  The public identifier.
     */
    public String extractPublicIdentifier() {
        return publicIdentifier.getEncapsulatedObject();
    }

    /***
     * Getter for the {@link RTreePolicy} of the {@link APILayerMacaroon}.
     * @return  The {@link RTreePolicy}.
     */
    public RTreePolicy extractRTreePolicy() {
        return rTreePolicyMacaroonElement.getEncapsulatedObject();
    }

    /**
     * Method to check if an {@link APILayerMacaroon} is valid, given the macaroon secret.
     * @param   macaroonSecret
     *          The macaroon secret.
     * @return  True if the macaroon is valid; false otherwise.
     */
    public boolean isValid(@NotNull String macaroonSecret) {
        var generatedSignature = publicIdentifier.generateSignature(macaroonSecret);
        if (!publicIdentifier.getSignature().equals(generatedSignature)) return false;

        generatedSignature = rTreePolicyMacaroonElement.generateSignature(generatedSignature);
        return rTreePolicyMacaroonElement.getSignature().equals(generatedSignature);
    }
}
