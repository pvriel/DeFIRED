package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Class representing a manager for {@link APILayerMacaroon} instances.
 */
public class APILayerMacaroonManager {

    private final static int MACAROONS_IDENTIFIERS_AND_SECRETS_LENGTH = 128;

    private final Map<String, String> storedMacaroonSecretPublicIdentifierPairs = Collections.synchronizedMap(new HashMap<>());

    /**
     * Method to register an {@link RTreePolicy} with the {@link APILayerMacaroonManager}.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} to register.
     * @return  The resulting {@link APILayerMacaroon}.
     */
    public synchronized APILayerMacaroon registerPolicy(@NotNull RTreePolicy rTreePolicy) {
        String macaroonPublicIdentifier = null;
        while (macaroonPublicIdentifier == null || storedMacaroonSecretPublicIdentifierPairs.containsKey(macaroonPublicIdentifier))
            macaroonPublicIdentifier = RandomStringUtils.randomAlphanumeric(MACAROONS_IDENTIFIERS_AND_SECRETS_LENGTH);

        String macaroonSecret = null;
        while (macaroonSecret == null || (storedMacaroonSecretPublicIdentifierPairs.containsKey(macaroonPublicIdentifier) &&
                storedMacaroonSecretPublicIdentifierPairs.get(macaroonPublicIdentifier).equals(macaroonSecret)))
            macaroonSecret = RandomStringUtils.randomAlphanumeric(MACAROONS_IDENTIFIERS_AND_SECRETS_LENGTH);

        var macaroon = new APILayerMacaroon(macaroonSecret, macaroonPublicIdentifier, rTreePolicy);

        storedMacaroonSecretPublicIdentifierPairs.put(macaroonPublicIdentifier, macaroonSecret);
        return macaroon;
    }

    /**
     * Method to verify an {@link APILayerMacaroon} and return its {@link RTreePolicy}.
     * @param   macaroon
     *          The {@link APILayerMacaroon}.
     * @return  The verified {@link RTreePolicy} of the {@link APILayerMacaroon}.
     * @throws  IllegalArgumentException
     *          If the {@link APILayerMacaroon} is not valid.
     */
    public synchronized @NotNull RTreePolicy returnVerifiedPolicy(@NotNull APILayerMacaroon macaroon) throws IllegalArgumentException {
        var publicMacaroonIdentifier = macaroon.extractPublicIdentifier();
        if (!storedMacaroonSecretPublicIdentifierPairs.containsKey(publicMacaroonIdentifier))
            throw new IllegalArgumentException(String.format("Macaroon identifier (%s) unknown.", publicMacaroonIdentifier));

        var macaroonSecret = storedMacaroonSecretPublicIdentifierPairs.get(publicMacaroonIdentifier);
        if (macaroon.isValid(macaroonSecret)) return macaroon.extractRTreePolicy();
        throw new IllegalArgumentException("Invalid macaroon.");
    }
}
