package vrielynckpieterjan.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.encryptionlayer.schemes.WIBEDecryptableSegment;

import java.io.Serializable;

/**
 * Class representing an non-encrypted version of the AES encryption information segment of the {@link IssuerPartAttestation}.
 */
public class AESEncryptionInformationSegmentAttestation implements Serializable {

    private final String partition;
    private final IBEDecryptableSegment<Pair<String, String>> aesKeyInformation;

    /**
     * Constructor for the {@link AESEncryptionInformationSegmentAttestation} class.
     * @param   rTreePolicy
     *          The {@link RTreePolicy} instance to generate the partition with.
     * @param   aesKeys
     *          The AES keys which should be stored in the AES key information segment.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link IssuerPartAttestation},
     *          used to encrypt the AES key information segment with.
     * @throws  IllegalArgumentException
     *          If the AES key information segment could not be encrypted using the provided arguments.
     */
    public AESEncryptionInformationSegmentAttestation(@NotNull RTreePolicy rTreePolicy,
                                                      @NotNull Pair<String, String> aesKeys,
                                                      @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver)
        throws IllegalArgumentException {
        partition = rTreePolicy.toString();
        aesKeyInformation = new IBEDecryptableSegment<>(aesKeys, publicEntityIdentifierReceiver, rTreePolicy.toString());
    }

    /**
     * Getter for the partition.
     * @return  The partition.
     */
    public String getPartition() {
        return partition;
    }

    /**
     * Getter for the encrypted version of the AES key information segment.
     * @return  The encrypted version of the AES key information segment as a {@link IBEDecryptableSegment} instance.
     */
    public IBEDecryptableSegment<Pair<String, String>> getAesKeyInformation() {
        return aesKeyInformation;
    }

    /**
     * Method to encrypt this {@link AESEncryptionInformationSegmentAttestation} instance.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link IssuerPartAttestation}.
     * @param   ibeIdentifier
     *          The WIBE identifier to encrypt this {@link AESEncryptionInformationSegmentAttestation} with.
     * @return  The encrypted version of this instance as an {@link WIBEDecryptableSegment}.
     * @throws  IllegalArgumentException
     *          If this instance could not be encrypted using the provided arguments.
     */
    public @NotNull WIBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> encrypt(
            @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
            @NotNull RTreePolicy ibeIdentifier) throws IllegalArgumentException {
        return new WIBEDecryptableSegment<>(this, publicEntityIdentifierReceiver, ibeIdentifier);
    }
}
