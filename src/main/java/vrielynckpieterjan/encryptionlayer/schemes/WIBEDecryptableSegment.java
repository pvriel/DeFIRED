package vrielynckpieterjan.encryptionlayer.schemes;

import cryptid.ibe.domain.*;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Class representing a WIBE {@link DecryptableSegment}.
 * @param       <DecryptedObjectType>
 *              The type of the decrypted version of the {@link IBEDecryptableSegment}.
 * @implNote    This class does not extend the {@link CipherEncryptedSegment} class.
 *              The {@link CipherEncryptedSegment} requires its subclasses to be able to encrypt / decrypt byte arrays,
 *              while the used library for the IBE encryption (CryptID) only supports Strings.
 *              Even though it's theoretically possible to allow this class to extend the {@link CipherEncryptedSegment} class,
 *              this would require some additional (de-)serialization and thus would cause a performance hit.
 * @implNote    Due to the similarities between the two classes, the encryption / decryption parts of this
 *              class are implemented using the methods of the {@link IBEDecryptableSegment} class.
 */
public class WIBEDecryptableSegment<DecryptedObjectType extends Serializable>
        implements DecryptableSegment<DecryptedObjectType, Triple<PublicParameters, BigInteger, RTreePolicy>> {

    private final IBEDecryptableSegment<DecryptedObjectType> encryptedSegment;

    /**
     * Constructor for the {@link WIBEDecryptableSegment} class.
     *
     * @param originalObject             The original object to encrypt.
     * @param publicParametersRTreePolicyPair The key to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public WIBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull Pair<PublicParameters, RTreePolicy> publicParametersRTreePolicyPair)
            throws IllegalArgumentException {
        Pair<PublicParameters, String> ibeEncryptionParameters = new ImmutablePair<>(
                publicParametersRTreePolicyPair.getLeft(), publicParametersRTreePolicyPair.getRight().toString());
        encryptedSegment = new IBEDecryptableSegment<>(originalObject, ibeEncryptionParameters);
    }

    /**
     * Constructor for the {@link WIBEDecryptableSegment} class.
     *
     * @param originalObject             The original object to encrypt.
     * @param publicEntityIdentifier The {@link PublicEntityIdentifier} to encrypt the original object with.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} to encrypt the original object with.
     * @throws IllegalArgumentException If an illegal key was provided.
     */
    public WIBEDecryptableSegment(@NotNull DecryptedObjectType originalObject, @NotNull PublicEntityIdentifier publicEntityIdentifier,
                                  @NotNull RTreePolicy rTreePolicy) throws IllegalArgumentException {
        this(originalObject, new ImmutablePair<>(publicEntityIdentifier.getWIBEIdentifier(), rTreePolicy));
    }

    @Override
    /**
     * @implNote    The provided {@link RTreePolicy} remains unchanged during the invocation of this method.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull Triple<PublicParameters, BigInteger, RTreePolicy> publicParametersBigIntegerRTreePolicyTriple)
            throws IllegalArgumentException {
        // Try to decrypt the encryptedSegment using every possible variant of the provided RTree policy.
        var equallyOrLessStrictPolicies = publicParametersBigIntegerRTreePolicyTriple.getRight().generateRTreePolicyVariations();
        Triple<PublicParameters, BigInteger, String> currentDecryptionParametersIBEEncryptedSegment;

        for (var currentRTreePolicy: equallyOrLessStrictPolicies) {
            currentDecryptionParametersIBEEncryptedSegment = new ImmutableTriple<>(
                    publicParametersBigIntegerRTreePolicyTriple.getLeft(),
                    publicParametersBigIntegerRTreePolicyTriple.getMiddle(),
                    currentRTreePolicy.toString());
            try {
                return encryptedSegment.decrypt(currentDecryptionParametersIBEEncryptedSegment);
            } catch (IllegalArgumentException ignored) {}
        }

        throw new IllegalArgumentException("WIBEEncryptedSegment could not be decrypted with the provided arguments.");
    }

    /**
     * Method to decrypt the {@link WIBEDecryptableSegment}.
     * @param   privateEntityIdentifier
     *          The {@link PrivateEntityIdentifier} to decrypt the {@link WIBEDecryptableSegment} with.
     * @param   rTreePolicy
     *          The WIBE identifier to decrypt the {@link WIBEDecryptableSegment} with.
     * @return  The decrypted and deserialized {@link WIBEDecryptableSegment}.
     * @throws  IllegalArgumentException
     *          If the provided key or WIBE identifier can't be used to decrypt the {@link WIBEDecryptableSegment}.
     */
    public @NotNull DecryptedObjectType decrypt(@NotNull PrivateEntityIdentifier privateEntityIdentifier, @NotNull RTreePolicy rTreePolicy)
        throws IllegalArgumentException {
        return this.decrypt(new ImmutableTriple<>(privateEntityIdentifier.getWIBEIdentifier().getLeft(),
                privateEntityIdentifier.getWIBEIdentifier().getRight(), rTreePolicy));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WIBEDecryptableSegment<?> that = (WIBEDecryptableSegment<?>) o;
        return encryptedSegment.equals(that.encryptedSegment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedSegment);
    }
}
