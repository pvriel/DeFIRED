package vrielynckpieterjan.encryptionlayer.schemes;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.applicationlayer.policy.PolicyRight;
import vrielynckpieterjan.applicationlayer.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.encryptionlayer.schemes.WIBEDecryptableSegment;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class WIBEDecryptableSegmentTest {

    @Test
    void encrypt() {
        String[] namespaceParts = new String[]{"A", "B", "C", "D"};
        RTreePolicy rTreePolicyOne = new RTreePolicy(PolicyRight.WRITE, namespaceParts[0]);
        RTreePolicy rTreePolicyTwo = new RTreePolicy(PolicyRight.WRITE, namespaceParts);

        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        Pair<PublicParameters, BigInteger> pkg = IBEDecryptableSegment.generatePKG();

        // User who knows policy WRITE://A/B/C/D, trying to decrypt a segment encrypted with WRITE://A/B/C/D: OK
        WIBEDecryptableSegment originalWIBEEncryptedSegment = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyTwo));
        String originalDecrypted = originalWIBEEncryptedSegment.decrypt(new ImmutableTriple<>(pkg.getLeft(), pkg.getRight(), rTreePolicyTwo));
        assertEquals(data, originalDecrypted);

        // User who knows policy WRITE://A/B/C/D, trying to decrypt a segment encrypted with WRITE://A : OK
        WIBEDecryptableSegment wibeEncryptedSegment = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyOne));
        String decrypted = wibeEncryptedSegment.decrypt(new ImmutableTriple<>(pkg.getLeft(), pkg.getRight(), rTreePolicyTwo));
        assertEquals(data, decrypted);
        // Other direction: NOK
        WIBEDecryptableSegment wibeEncryptedSegmentTwo = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyTwo));
        assertThrows(IllegalArgumentException.class, () -> wibeEncryptedSegmentTwo.decrypt(new ImmutableTriple<>(pkg.getLeft(),
                pkg.getRight(), rTreePolicyOne)));

        // User who knows policy READ://A/B/C/D, trying to decrypt a segment encrypted with WRITE://A : OK
        rTreePolicyTwo = new RTreePolicy(PolicyRight.READ, namespaceParts);
        wibeEncryptedSegment = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyOne));
        decrypted = wibeEncryptedSegment.decrypt(new ImmutableTriple<>(pkg.getLeft(), pkg.getRight(), rTreePolicyTwo));
        assertEquals(data, decrypted);
        // Other direction: NOK
        WIBEDecryptableSegment wibeEncryptedSegmentThree = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyTwo));
        assertThrows(IllegalArgumentException.class, () -> wibeEncryptedSegmentThree.decrypt(new ImmutableTriple<>(pkg.getLeft(),
                pkg.getRight(), rTreePolicyOne)));

        // User who knows policy WRITE://C/D, trying to decrypt a segment encrypted with WRITE://A/B: NOK
        RTreePolicy rTreePolicyThree = new RTreePolicy(PolicyRight.WRITE, namespaceParts[0], namespaceParts[1]);
        RTreePolicy rTreePolicyFour = new RTreePolicy(PolicyRight.WRITE, namespaceParts[2], namespaceParts[3]);
        WIBEDecryptableSegment wibeEncryptedSegmentFour = new WIBEDecryptableSegment(data, new ImmutablePair<>(pkg.getLeft(), rTreePolicyThree));
        assertThrows(IllegalArgumentException.class, () -> wibeEncryptedSegmentFour.decrypt(new ImmutableTriple<>(pkg.getLeft(),
                pkg.getRight(), rTreePolicyFour)));
    }
}