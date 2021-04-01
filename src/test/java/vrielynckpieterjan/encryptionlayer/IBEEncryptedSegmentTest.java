package vrielynckpieterjan.encryptionlayer;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class IBEEncryptedSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        Pair<PublicParameters, BigInteger> pkg = IBEEncryptedSegment.generatePKG();
        String identity = "WRITE://A/B";
        IBEEncryptedSegment ibeEncryptedSegment = new IBEEncryptedSegment(data,
                new ImmutablePair<>(pkg.getLeft(), identity));

        System.out.println(new String(SerializationUtils.serialize(ibeEncryptedSegment), StandardCharsets.UTF_8)); // Debug purposes.

        String decrypted = ibeEncryptedSegment.decrypt(new ImmutableTriple<>(pkg.getLeft(), pkg.getRight(), identity));
        assertEquals(data, decrypted);
    }
}