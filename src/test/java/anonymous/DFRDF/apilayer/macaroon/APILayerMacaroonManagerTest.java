package anonymous.DFRDF.apilayer.macaroon;

import org.junit.jupiter.api.Test;
import anonymous.DFRDF.applicationlayer.attestation.policy.PolicyRight;
import anonymous.DFRDF.applicationlayer.attestation.policy.RTreePolicy;

import static org.junit.jupiter.api.Assertions.*;

class APILayerMacaroonManagerTest {

    @Test
    void registerPolicy() {
        APILayerMacaroonManager apiLayerMacaroonManager = new APILayerMacaroonManager();

        RTreePolicy rTreePolicy = new RTreePolicy(PolicyRight.WRITE, "A", "B", "C");
        APILayerMacaroon macaroon = apiLayerMacaroonManager.registerPolicy(rTreePolicy);

        assertEquals(rTreePolicy, apiLayerMacaroonManager.returnVerifiedPolicy(macaroon));

        APILayerMacaroon unregisteredMacaroon = new APILayerMacaroon("secret", "publicIdentifier",
                new RTreePolicy(PolicyRight.WRITE, "A", "B"));
        assertThrows(IllegalArgumentException.class, () -> apiLayerMacaroonManager.returnVerifiedPolicy(unregisteredMacaroon));
    }
}