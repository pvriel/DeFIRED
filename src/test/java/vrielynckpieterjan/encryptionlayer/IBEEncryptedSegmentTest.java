package vrielynckpieterjan.encryptionlayer;

import cryptid.ibe.domain.PrivateKey;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class IBEEncryptedSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        String identifier = "WRITE://cloud storage service provider/user";
        PrivateKey privateKey = IBEEncryptedSegment.convertIdentifierToPrivateKey(identifier);
        IBEEncryptedSegment ibeEncryptedSegment = new IBEEncryptedSegment(data, identifier);

        System.out.println(new String(SerializationUtils.serialize(ibeEncryptedSegment))); // Debug purposes; not actually part of the test.

        String decryptedSegment = ibeEncryptedSegment.decrypt(privateKey);
        assertEquals(data, decryptedSegment);
    }
}