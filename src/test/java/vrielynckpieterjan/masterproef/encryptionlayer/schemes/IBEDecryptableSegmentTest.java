package vrielynckpieterjan.masterproef.encryptionlayer.schemes;

import cryptid.CryptID;
import cryptid.ibe.IdentityBasedEncryption;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PublicParameters;
import cryptid.ibe.domain.SecurityLevel;
import cryptid.ibe.exception.SetupException;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

class IBEDecryptableSegmentTest {

    @Test
    void encrypt() {
        String data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut " +
                "labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi " +
                "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa " +
                "qui officia deserunt mollit anim id est laborum.";
        Pair<PublicParameters, BigInteger> pkg = IBEDecryptableSegment.generatePKG();
        String identity = "WRITE://A/B";
        IBEDecryptableSegment<String> ibeDecryptableSegment = new IBEDecryptableSegment(data,
                new ImmutablePair<>(pkg.getLeft(), identity));

        System.out.println(new String(SerializationUtils.serialize(ibeDecryptableSegment), StandardCharsets.UTF_8)); // Debug purposes.

        String decrypted = ibeDecryptableSegment.decrypt(new ImmutableTriple<>(pkg.getLeft(), pkg.getRight(), identity));
        assertEquals(data, decrypted);
    }

    @Test
    void speedPrivateKeyGenerationTest() throws SetupException {
        IdentityBasedEncryption ibe = CryptID.setupBonehFranklin(SecurityLevel.LOWEST);

        String message = "Ironic.";
        String identity = "darth.plagueis@sith.com";

        // Encrypt the message
        CipherTextTuple cipherText = ibe.encrypt(message, identity);

        // Obtain the private key corresponding to the identity
        int amountOfRounds = 100;
        double result = 0.0;

        for (int i = 0; i < amountOfRounds; i ++) {
            long startTime = System.currentTimeMillis();
            ibe.extract(identity);
            long endTime = System.currentTimeMillis();
            result += endTime - startTime;
        }

        result /= amountOfRounds;
        System.out.println(result);


    }
}