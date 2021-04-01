package vrielynckpieterjan.encryptionlayer;

import cryptid.ibe.domain.PrivateKey;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.policy.RTreePolicy;

import static vrielynckpieterjan.applicationlayer.policy.PolicyRight.READ;
import static vrielynckpieterjan.applicationlayer.policy.PolicyRight.WRITE;

/**
 * Class representing a WIBE {@link EncryptedSegment}.
 * @implNote
 *          The {@link WIBEEncryptedSegment} class is implemented using
 *          {@link IBEEncryptedSegment} instances.
 */
public class WIBEEncryptedSegment extends EncryptedSegment<String, RTreePolicy, RTreePolicy> {

    /**
     * Constructor for the {@link WIBEEncryptedSegment} class.
     *
     * @param originalObject The original object to encrypt.
     * @param rTreePolicy    The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public WIBEEncryptedSegment(@NotNull String originalObject, @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        super(originalObject, rTreePolicy);
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        // TODO: same problem as with the encrypt method of the IBEEncryptedSegment class.
        String originalObject = SerializationUtils.deserialize(serializedOriginalObject);

        IBEEncryptedSegment ibeEncryptedSegment = new IBEEncryptedSegment(originalObject, rTreePolicy.toString());
        return SerializationUtils.serialize(ibeEncryptedSegment);
    }

    @Override
    /**
     * @implNote    The provided {@link RTreePolicy} instance remains unchanged during this method invocation.
     */
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        // TODO: same problem as with the decrypt method of the IBEEncryptedSegment class.
        IBEEncryptedSegment ibeEncryptedSegment = SerializationUtils.deserialize(encryptedSegment);
        rTreePolicy = rTreePolicy.clone(); // Cf. implementation node.

        // Try all possibilities of RTree policies (equal, less strict, write / read) to decrypt the IBEEncryptedSegment.
        for (int i = 0; i < rTreePolicy.getAmountOfNamespaceDirectories(); i ++) {
            // Try both read / write variant, if relevant.
            for (int j = 0; j < 2; j ++) {
                PrivateKey privateKey = IBEEncryptedSegment.convertIdentifierToPrivateKey(rTreePolicy.toString());
                try {
                    String decryptedString = ibeEncryptedSegment.decrypt(privateKey);
                    return SerializationUtils.serialize(decryptedString);
                } catch (Exception ignored) {}

                // Change from read / write to the write / read variant of the current rTreePolicy variable.
                if (j == 0 && rTreePolicy.getPolicyRight().equals(WRITE)) {
                    // There's no point in trying out the read-variant of the RTree policy in this if-statement block.
                    // Because of the way in which the WIBE encryption scheme is used by this framework,
                    // the provided rTreePolicy argument should represent a policy which is equal / more strict
                    // than the policy of the RTreePolicy instance which was used to encrypt this WIBEEncryptedSegment
                    // instance in the first place.
                    // Since a WRITE policy is less strict than a READ policy, this means that no READ policies
                    // were used to encrypt this WIBEEncryptedSegment instance.
                    break; // j-loop.
                } else rTreePolicy.setPolicyRight(rTreePolicy.getPolicyRight().equals(WRITE)? READ:WRITE);
            }

            // BUG FIX: WRITE://A ==> rTreePolicy.getAmountOfNamespaceDirectories() == 1,
            // but A does not have a namespace parent directory and this would cause an IllegalStateException otherwise.
            if (rTreePolicy.getAmountOfNamespaceDirectories() > 1)
                rTreePolicy = rTreePolicy.generateRTreePolicyForNamespaceParentDirectory();
            else break;
        }

        throw new IllegalArgumentException("The WIBEEncryptedSegment could not be decrypted using the provided" +
                " RTreePolicy instance.");
    }
}
