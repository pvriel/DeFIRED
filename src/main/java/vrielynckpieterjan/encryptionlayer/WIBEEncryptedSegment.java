package vrielynckpieterjan.encryptionlayer;

import cryptid.ibe.IbeClient;
import cryptid.ibe.PrivateKeyGenerator;
import cryptid.ibe.domain.CipherTextTuple;
import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.PublicParameters;
import cryptid.ibe.exception.ComponentConstructionException;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.policy.RTreePolicy;

import java.math.BigInteger;
import java.util.Optional;

import static vrielynckpieterjan.applicationlayer.policy.PolicyRight.*;

/**
 * Class representing a WIBE {@link EncryptedSegment}.
 */
public class WIBEEncryptedSegment
        extends EncryptedSegment<String, Pair<PublicParameters, RTreePolicy>, Triple<PublicParameters, BigInteger, RTreePolicy>> {

    /**
     * Constructor for the {@link WIBEEncryptedSegment} class.
     *
     * @param originalObject                  The original object to encrypt.
     * @param publicParametersRTreePolicyPair The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public WIBEEncryptedSegment(@NotNull String originalObject, @NotNull Pair<PublicParameters, RTreePolicy> publicParametersRTreePolicyPair) throws IllegalArgumentException {
        super(originalObject, publicParametersRTreePolicyPair);
    }

    @Override
    protected byte[] encrypt(byte[] serializedOriginalObject, @NotNull Pair<PublicParameters, RTreePolicy> publicParametersRTreePolicyPair) throws IllegalArgumentException {
        // TODO: optimize this. serializedOriginalObject is already a serialized String.
        String originalObject = SerializationUtils.deserialize(serializedOriginalObject);

        try {
            // Construct the necessary part of the PKG to encrypt the String.
            IbeClient ibeClient = IBEEncryptedSegment.componentFactory.obtainClient(publicParametersRTreePolicyPair.getLeft());
            // Actual encryption part.
            RTreePolicy policyToEncryptWith = publicParametersRTreePolicyPair.getRight();
            CipherTextTuple cipherTextTuple = ibeClient.encrypt(originalObject, policyToEncryptWith.toString());
            return SerializationUtils.serialize(cipherTextTuple);
        } catch (ComponentConstructionException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    /**
     * @implNote    The provided {@link RTreePolicy} remains unchanged during the invocation of this method.
     */
    protected byte[] decrypt(byte[] encryptedSegment, @NotNull Triple<PublicParameters, BigInteger, RTreePolicy> publicParametersBigIntegerRTreePolicyTriple) throws IllegalArgumentException {
        CipherTextTuple cipherTextTuple = SerializationUtils.deserialize(encryptedSegment);

        // Construct the necessary part of the PKG to decrypt the CipherTextTuple.
        IbeClient ibeClient;
        PrivateKeyGenerator privateKeyGenerator;
        try {
            ibeClient = IBEEncryptedSegment.componentFactory.obtainClient(publicParametersBigIntegerRTreePolicyTriple.getLeft());
            privateKeyGenerator = IBEEncryptedSegment.componentFactory.obtainPrivateKeyGenerator(
                    publicParametersBigIntegerRTreePolicyTriple.getLeft(), publicParametersBigIntegerRTreePolicyTriple.getMiddle());
        } catch(ComponentConstructionException e){
            throw new IllegalArgumentException(e);
        }

        // The actual decryption part.
        // Consider all policies related to the provided RTreePolicy object.
        RTreePolicy rTreePolicy = publicParametersBigIntegerRTreePolicyTriple.getRight();
        rTreePolicy = rTreePolicy.clone(); // Cf. implementation note.
        while (true) {
            // Consider both the READ- and WRITE-variant of the current rTreePolicy variable, for now.
            for (int i = 0; i < 2; i ++) {
                PrivateKey privateKey = privateKeyGenerator.extract(rTreePolicy.toString());
                Optional<String> optionalDecryptedString = ibeClient.decrypt(privateKey, cipherTextTuple);
                if (optionalDecryptedString.isPresent()) {
                    String decrypted = optionalDecryptedString.get();
                    return SerializationUtils.serialize(decrypted);
                }

                // Should we also consider the other variant?
                if (i == 0 && rTreePolicy.getPolicyRight().equals(WRITE)) {
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
                } else rTreePolicy.setPolicyRight(rTreePolicy.getPolicyRight().equals(WRITE)? READ:WRITE);
            }

            if (rTreePolicy.getAmountOfNamespaceDirectories() <= 1)
                throw new IllegalArgumentException("WIBEEncryptedSegment could not be decrypted with the provided arguments.");
            rTreePolicy = rTreePolicy.generateRTreePolicyForNamespaceParentDirectory();
        }
    }
}
