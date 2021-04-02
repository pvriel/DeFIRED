package vrielynckpieterjan.encryptionlayer;

import cryptid.ibe.domain.*;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.policy.RTreePolicy;

import java.math.BigInteger;

import static vrielynckpieterjan.applicationlayer.policy.PolicyRight.READ;
import static vrielynckpieterjan.applicationlayer.policy.PolicyRight.WRITE;

/**
 * Class representing a WIBE {@link DecryptableSegment}.
 * @implNote    This class does not extend the {@link CipherEncryptedSegment} class.
 *              The {@link CipherEncryptedSegment} requires its subclasses to be able to encrypt / decrypt byte arrays,
 *              while the used library for the IBE encryption (CryptID) only supports Strings.
 *              Even though it's theoretically possible to allow this class to extend the {@link CipherEncryptedSegment} class,
 *              this would require some additional (de-)serialization and thus would cause a performance hit.
 * @implNote    Due to the similarities between the two classes, the encryption / decryption parts of this
 *              class are implemented using the methods of the {@link IBEDecryptableSegment} class.
 */
public class WIBEDecryptableSegment
        implements DecryptableSegment<String, Triple<PublicParameters, BigInteger, RTreePolicy>> {

    private final IBEDecryptableSegment encryptedSegment;

    /**
     * Constructor for the {@link WIBEDecryptableSegment} class.
     *
     * @param originalObject             The original object to encrypt.
     * @param publicParametersRTreePolicyPair The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public WIBEDecryptableSegment(@NotNull String originalObject, @NotNull Pair<PublicParameters, RTreePolicy> publicParametersRTreePolicyPair)
            throws IllegalArgumentException {
        Pair<PublicParameters, String> ibeEncryptionParameters = new ImmutablePair<>(
                publicParametersRTreePolicyPair.getLeft(), publicParametersRTreePolicyPair.getRight().toString());
        encryptedSegment = new IBEDecryptableSegment(originalObject, ibeEncryptionParameters);
    }

    @Override
    /**
     * @implNote    The provided {@link RTreePolicy} remains unchanged during the invocation of this method.
     */
    public @NotNull String decrypt(@NotNull Triple<PublicParameters, BigInteger, RTreePolicy> publicParametersBigIntegerRTreePolicyTriple)
            throws IllegalArgumentException {
        // Try to decrypt the encryptedSegment using every possible variant of the provided RTree policy.
        RTreePolicy currentRTreePolicy = publicParametersBigIntegerRTreePolicyTriple.getRight().clone();
        Triple<PublicParameters, BigInteger, String> currentDecryptionParametersIBEEncryptedSegment;
        while (true) {
            // Consider both the READ- and WRITE-variant of the current RTreePolicy, for now at least.
            for (int i = 0; i < 2; i ++) {
                currentDecryptionParametersIBEEncryptedSegment = new ImmutableTriple<>(
                        publicParametersBigIntegerRTreePolicyTriple.getLeft(),
                        publicParametersBigIntegerRTreePolicyTriple.getMiddle(),
                        currentRTreePolicy.toString());
                try {
                    return encryptedSegment.decrypt(currentDecryptionParametersIBEEncryptedSegment);
                } catch (IllegalArgumentException ignored) { }

                // Should we also consider the other variant?
                if (i == 0 && currentRTreePolicy.getPolicyRight().equals(WRITE)) {
                    // No, because:
                    // - According to the design of the framework, only RTree policies can be used to decrypt this
                    //      WIBEEncryptedSegment which are equally or even more strict than the RTree policy object
                    //      which was used to encrypt this WIBEEncryptedSegment instance in the first place.
                    // - By providing a WRITE RTreePolicy instance as argument for this method invocation, the assumption
                    //      is therefore made that the object was originally encrypted using a WRITE RTreePolicy instance,
                    //      since WRITE policies are less strict than READ policies.
                    // Therefore, don't waste time trying READ policies to decrypt this WIBEEncryptedSegment instance,
                    // cause that will never work anyways.
                    break; // Break the i-loop.
                } else currentRTreePolicy.setPolicyRight(currentRTreePolicy.getPolicyRight().equals(WRITE)? READ:WRITE);
            }

            if (currentRTreePolicy.getAmountOfNamespaceDirectories() > 1)
                currentRTreePolicy = currentRTreePolicy.generateRTreePolicyForNamespaceParentDirectory();
            else break;
        }

        throw new IllegalArgumentException("WIBEEncryptedSegment could not be decrypted with the provided arguments.");
    }
}
