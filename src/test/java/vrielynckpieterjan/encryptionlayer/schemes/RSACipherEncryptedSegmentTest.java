package vrielynckpieterjan.encryptionlayer.schemes;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.encryptionlayer.schemes.RSACipherEncryptedSegment;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class RSACipherEncryptedSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        KeyPair keyPair = RSACipherEncryptedSegment.generateKeyPair();
        RSACipherEncryptedSegment<String> rsaEncryptedSegment = new RSACipherEncryptedSegment<>(data, keyPair.getPublic());

        System.out.println(new String(SerializationUtils.serialize(rsaEncryptedSegment))); // Debug purposes; not actually part of the test.

        // TODO: does this also work for non-String objects?
        String decryptedSegment = rsaEncryptedSegment.decrypt(keyPair.getPrivate());
        assertEquals(data, decryptedSegment);
    }
}