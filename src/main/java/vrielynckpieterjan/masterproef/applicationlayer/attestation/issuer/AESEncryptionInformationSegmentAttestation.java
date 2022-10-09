package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Class representing an non-encrypted version of the AES encryption information segment of the {@link IssuerPartAttestation}.
 */
public class AESEncryptionInformationSegmentAttestation implements Exportable {

    private final Pair<String, String> aesKeyInformation;

    protected AESEncryptionInformationSegmentAttestation(@NotNull Pair<String, String> aesKeyInformation) {
        this.aesKeyInformation = aesKeyInformation;
    }

    /**
     * Constructor for the {@link AESEncryptionInformationSegmentAttestation} class.
     *
     * @param aesKeys The AES keys which should be stored in the AES key information segment.
     */
    public AESEncryptionInformationSegmentAttestation(@NotNull RTreePolicy rTreePolicy,
                                                      @NotNull Pair<String, String> aesKeys,
                                                      @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver)
            throws IllegalArgumentException {
        aesKeyInformation = aesKeys;
    }

    @NotNull
    public static AESEncryptionInformationSegmentAttestation deserialize(@NotNull ByteBuffer byteBuffer) {
        byte[] keyAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(keyAsByteArray);
        String key = new String(keyAsByteArray, StandardCharsets.UTF_8);

        byte[] valueAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(valueAsByteArray);
        String value = new String(valueAsByteArray, StandardCharsets.UTF_8);

        return new AESEncryptionInformationSegmentAttestation(new ImmutablePair<>(key, value));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AESEncryptionInformationSegmentAttestation)) return false;

        AESEncryptionInformationSegmentAttestation that = (AESEncryptionInformationSegmentAttestation) o;

        return getAesKeyInformation().equals(that.getAesKeyInformation());
    }

    @Override
    public int hashCode() {
        return getAesKeyInformation().hashCode();
    }

    /**
     * Getter for the AES key information segment.
     *
     * @return The AES key information segment.
     */
    public Pair<String, String> getAesKeyInformation() {
        return aesKeyInformation;
    }

    /**
     * Method to encrypt this {@link AESEncryptionInformationSegmentAttestation} instance.
     *
     * @param publicEntityIdentifierReceiver The {@link PublicEntityIdentifier} of the user receiving the {@link IssuerPartAttestation}.
     * @param ibeIdentifier                  The IBE identifier to encrypt this {@link AESEncryptionInformationSegmentAttestation} with.
     * @return The encrypted version of this instance as an {@link IBEDecryptableSegment}.
     * @throws IllegalArgumentException If this instance could not be encrypted using the provided arguments.
     */
    public @NotNull IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> encrypt(
            @NotNull PublicEntityIdentifier publicEntityIdentifierReceiver,
            @NotNull RTreePolicy ibeIdentifier) throws IllegalArgumentException {
        return new IBEDecryptableSegment<>(this, publicEntityIdentifierReceiver, ibeIdentifier.toString());
    }

    @Override
    public byte[] serialize() throws IOException {
        byte[] keyAsByteArray = aesKeyInformation.getLeft().getBytes(StandardCharsets.UTF_8);
        byte[] valueAsByteArray = aesKeyInformation.getRight().getBytes(StandardCharsets.UTF_8);

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + keyAsByteArray.length + valueAsByteArray.length);
        byteBuffer.putInt(keyAsByteArray.length);
        byteBuffer.put(keyAsByteArray);
        byteBuffer.put(valueAsByteArray);

        return byteBuffer.array();
    }
}
