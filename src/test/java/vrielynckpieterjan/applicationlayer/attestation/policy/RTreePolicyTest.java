package vrielynckpieterjan.applicationlayer.attestation.policy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight.*;

class RTreePolicyTest {

    @Test
    void generateRTreePolicyForNamespaceParentDirectory() {
        String[] firstNamespaceCollection = new String[]{"cloud service provider A", "user A"};
        RTreePolicy rTreePolicy = new RTreePolicy(READ, firstNamespaceCollection[0], firstNamespaceCollection[1]);
        assertEquals(String.format("%s://cloud service provider A/user A", READ.name()), rTreePolicy.toString());
        rTreePolicy = rTreePolicy.generateRTreePolicyForNamespaceParentDirectory();
        assertEquals(String.format("%s://cloud service provider A", READ.name()), rTreePolicy.toString());
        assertThrows(IllegalStateException.class, rTreePolicy::generateRTreePolicyForNamespaceParentDirectory);
    }

    @Test
    void coversRTreePolicy() {
        // 1) works with further delegations?
        String[] firstNamespaceCollection = new String[]{"cloud service provider A", "user A"};
        RTreePolicy cloudServicePolicy = new RTreePolicy(WRITE, firstNamespaceCollection[0]);
        RTreePolicy userPolicy = new RTreePolicy(WRITE, firstNamespaceCollection[0], firstNamespaceCollection[1]);
        assertTrue(cloudServicePolicy.coversRTreePolicy(userPolicy));
        assertFalse(userPolicy.coversRTreePolicy(cloudServicePolicy));

        // 2) works with different policy rights?
        userPolicy = new RTreePolicy(READ, firstNamespaceCollection[0], firstNamespaceCollection[1]);
        assertTrue(cloudServicePolicy.coversRTreePolicy(userPolicy));
        assertFalse(userPolicy.coversRTreePolicy(cloudServicePolicy));

        cloudServicePolicy = new RTreePolicy(READ, firstNamespaceCollection[0]);
        assertTrue(cloudServicePolicy.coversRTreePolicy(userPolicy));
        assertFalse(userPolicy.coversRTreePolicy(cloudServicePolicy));

        userPolicy = new RTreePolicy(WRITE, firstNamespaceCollection[0], firstNamespaceCollection[1]);
        assertFalse(cloudServicePolicy.coversRTreePolicy(userPolicy));
        assertFalse(userPolicy.coversRTreePolicy(cloudServicePolicy));

        // 3) works with different namespaces?
        cloudServicePolicy = new RTreePolicy(WRITE, firstNamespaceCollection[0], "user B");
        assertFalse(cloudServicePolicy.coversRTreePolicy(userPolicy));
        assertFalse(userPolicy.coversRTreePolicy(cloudServicePolicy));
    }

    @Test
    void testToString() {
        RTreePolicy rTreePolicy = new RTreePolicy(WRITE, "cloud service provider", "user");
        assertEquals(String.format("%s://cloud service provider/user", WRITE.name()), rTreePolicy.toString());
    }

    @Test
    void testFromString() {
        String expressedRTreePolicy = String.format("%s://A/B/C", WRITE.name());
        RTreePolicy encapsulatedPolicy = RTreePolicy.convertStringToRTreePolicy(expressedRTreePolicy);
        assertEquals(expressedRTreePolicy, encapsulatedPolicy.toString());
    }
}