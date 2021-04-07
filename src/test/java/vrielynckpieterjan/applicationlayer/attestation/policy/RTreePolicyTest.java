package vrielynckpieterjan.applicationlayer.attestation.policy;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static vrielynckpieterjan.applicationlayer.attestation.policy.PolicyRight.*;

class RTreePolicyTest {

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

    @Test
    void generateEquallyOrLessStrictVariations() {
        var originalPolicy = new RTreePolicy(READ, "A", "B");

        Set<RTreePolicy> expectedReturnValue = new HashSet<>();
        expectedReturnValue.add(originalPolicy);
        expectedReturnValue.add(new RTreePolicy(WRITE, "A", "B"));
        expectedReturnValue.add(new RTreePolicy(READ, "A"));
        expectedReturnValue.add(new RTreePolicy(WRITE, "A"));

        assertEquals(expectedReturnValue, originalPolicy.generateAllEquallyOrLessStrictRTreePolicies());
    }
}