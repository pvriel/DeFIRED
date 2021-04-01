package vrielynckpieterjan.encryptionlayer;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.applicationlayer.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.policy.RTreePolicy;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class WIBEEncryptedSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        String[] namespaceCombinations = new String[] {"A", "B", "C"};
        // WRITE://A/B/*
        RTreePolicy lessStrictPolicy = new RTreePolicy(PolicyRight.WRITE, namespaceCombinations[0], namespaceCombinations[1]);
        WIBEEncryptedSegment wibeEncryptedSegment = new WIBEEncryptedSegment(data, lessStrictPolicy);

        System.out.println(new String(SerializationUtils.serialize(wibeEncryptedSegment), StandardCharsets.UTF_8));

        // This should work, since we are using the same policy...
        String decrypted = wibeEncryptedSegment.decrypt(lessStrictPolicy);
        assertEquals(data, decrypted);

        // But this should also work with a more strict policy!
        // READ://A/B/C
        RTreePolicy moreStrictPolicy = new RTreePolicy(PolicyRight.READ, namespaceCombinations[0], namespaceCombinations[1],
                namespaceCombinations[2]);
        decrypted = wibeEncryptedSegment.decrypt(moreStrictPolicy);
        assertEquals(data, decrypted);

        // However, this should not work the other way around.
        // E.g. you can't decrypt a WIBEEncryptedSegment, encrypted with the policy WRITE://A/B/*,
        // using the policy WRITE://A/*.
        RTreePolicy lessLessStrictPolicy = new RTreePolicy(PolicyRight.WRITE, namespaceCombinations[0]);
        assertThrows(IllegalArgumentException.class, () -> wibeEncryptedSegment.decrypt(lessLessStrictPolicy));

        // We could also test if you can decrypt an WIBEEncryptedSegment with a completely irrelevant policy, which
        // should not be possible.
        // However, that's already tested by the previous section.
    }
}