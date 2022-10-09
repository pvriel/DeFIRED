package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class APILayerMacaroonTest {

    @Test
    void isValid() {
        var policy = new RTreePolicy(PolicyRight.WRITE, "A", "B", "C");
        var privateMacaroonSecret = RandomStringUtils.randomAlphanumeric(32);
        var publicIdentifierMacaroon = RandomStringUtils.randomAlphanumeric(32);

        var macaroon = new APILayerMacaroon(privateMacaroonSecret, publicIdentifierMacaroon, policy);
        assertTrue(macaroon.isValid(privateMacaroonSecret));
        assertFalse(macaroon.isValid(publicIdentifierMacaroon));
    }
}