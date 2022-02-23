package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;

import static org.junit.jupiter.api.Assertions.*;

class AESCipherEncryptedSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        String key = "magicalKey";
        AESCipherEncryptedSegment<String> aesEncryptedSegment = new AESCipherEncryptedSegment<>(data, key);

        System.out.println(new String(SerializationUtils.serialize(aesEncryptedSegment))); // Debug purposes; not actually part of the test.

        String decryptedSegment = aesEncryptedSegment.decrypt(key);
        assertEquals(data, decryptedSegment);
    }

    @Test
    void nonStringEncrypt() {
        PublicEntityIdentifier publicEntityIdentifier = EntityIdentifier.generateEntityIdentifierPair("").getRight();
        String key = "magicalKey";
        AESCipherEncryptedSegment<PublicEntityIdentifier> aesCipherEncryptedSegment = new AESCipherEncryptedSegment<>(
                publicEntityIdentifier, key);
        PublicEntityIdentifier decryptedSegment = aesCipherEncryptedSegment.decrypt(key);
        assertEquals(decryptedSegment.getNamespaceServiceProviderEmailAddressUserConcatenation(), publicEntityIdentifier.getNamespaceServiceProviderEmailAddressUserConcatenation());
        assertEquals(decryptedSegment.getRSAIdentifier(), publicEntityIdentifier.getRSAIdentifier());
        assertEquals(decryptedSegment.getIBEIdentifier(), publicEntityIdentifier.getIBEIdentifier());
        assertEquals(decryptedSegment, publicEntityIdentifier);
    }
}