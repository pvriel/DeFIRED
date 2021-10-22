package anonymous.DFRDF.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import anonymous.DFRDF.applicationlayer.attestation.policy.RTreePolicy;
import anonymous.DFRDF.encryptionlayer.entities.PublicEntityIdentifier;
import anonymous.DFRDF.encryptionlayer.schemes.IBEDecryptableSegment;

import java.io.Serializable;

/**
 * Class representing an non-encrypted version of the AES encryption information segment of the {@link IssuerPartAttestation}.
 */
public class AESEncryptionInformationSegmentAttestation implements Serializable {

    private final Pair<String, String> aesKeyInformation;

    /**
     * Constructor for the {@link AESEncryptionInformationSegmentAttestation} class.
     * @param   aesKeys
     *          The AES keys which should be stored in the AES key information segment.
     */
    public AESEncryptionInformationSegmentAttestation(@NotNull RTreePolicy rTreePolicy,
                                                      @NotNull Pair<String, String> aesKeys,
                                                      @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver)
        throws IllegalArgumentException {
        aesKeyInformation = aesKeys;
    }

    /**
     * Getter for the AES key information segment.
     * @return  The AES key information segment.
     */
    public Pair<String, String> getAesKeyInformation() {
        return aesKeyInformation;
    }

    /**
     * Method to encrypt this {@link AESEncryptionInformationSegmentAttestation} instance.
     * @param   publicEntityIdentifierReceiver
     *          The {@link PublicEntityIdentifier} of the user receiving the {@link IssuerPartAttestation}.
     * @param   ibeIdentifier
     *          The IBE identifier to encrypt this {@link AESEncryptionInformationSegmentAttestation} with.
     * @return  The encrypted version of this instance as an {@link IBEDecryptableSegment}.
     * @throws  IllegalArgumentException
     *          If this instance could not be encrypted using the provided arguments.
     */
    public @NotNull IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> encrypt(
            @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
            @NotNull RTreePolicy ibeIdentifier) throws IllegalArgumentException {
        return new IBEDecryptableSegment<>(this, publicEntityIdentifierReceiver, ibeIdentifier.toString());
    }
}
