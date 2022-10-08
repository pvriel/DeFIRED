package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Class representing a macaroon object for the API layer.
 */
public class APILayerMacaroon implements Exportable {

    private final PublicIdentifierMacaroonElement publicIdentifier;
    private final RTreePolicyMacaroonElement rTreePolicyMacaroonElement;
    private final String signature;

    /**
     * Constructor for the {@link APILayerMacaroon} class.
     *
     * @param macaroonSecret           The macaroon secret.
     * @param macaroonPublicIdentifier The public identifier of the macaroon.
     * @param rTreePolicy              The encapsulated {@link RTreePolicy}.
     */
    public APILayerMacaroon(@NotNull String macaroonSecret,
                            @NotNull String macaroonPublicIdentifier,
                            @NotNull RTreePolicy rTreePolicy) {
        publicIdentifier = new PublicIdentifierMacaroonElement(macaroonSecret, macaroonPublicIdentifier);
        rTreePolicyMacaroonElement = new RTreePolicyMacaroonElement(publicIdentifier, rTreePolicy);

        var tempSignature = publicIdentifier.generateSignature(macaroonSecret);
        signature = rTreePolicyMacaroonElement.generateSignature(tempSignature);
    }

    protected APILayerMacaroon(@NotNull PublicIdentifierMacaroonElement publicIdentifier,
                               @NotNull RTreePolicyMacaroonElement rTreePolicyMacaroonElement,
                               @NotNull String signature) {
        this.publicIdentifier = publicIdentifier;
        this.rTreePolicyMacaroonElement = rTreePolicyMacaroonElement;
        this.signature = signature;
    }

    @NotNull
    public static APILayerMacaroon deserialize(@NotNull ByteBuffer byteBuffer) throws IOException {
        byte[] firstElementAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(firstElementAsByteArray);
        PublicIdentifierMacaroonElement publicIdentifier = ExportableUtils.deserialize(firstElementAsByteArray, PublicIdentifierMacaroonElement.class);

        byte[] secondElementAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(secondElementAsByteArray);
        RTreePolicyMacaroonElement rTreePolicyMacaroonElement = ExportableUtils.deserialize(secondElementAsByteArray, RTreePolicyMacaroonElement.class);

        byte[] signatureAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(signatureAsByteArray);
        String signature = new String(signatureAsByteArray, StandardCharsets.UTF_8);

        return new APILayerMacaroon(publicIdentifier, rTreePolicyMacaroonElement, signature);
    }

    /**
     * Getter for the public identifier of the macaroon.
     *
     * @return The public identifier.
     */
    public String extractPublicIdentifier() {
        return publicIdentifier.getEncapsulatedObject();
    }

    /***
     * Getter for the {@link RTreePolicy} of the {@link APILayerMacaroon}.
     * @return The {@link RTreePolicy}.
     */
    public RTreePolicy extractRTreePolicy() {
        return rTreePolicyMacaroonElement.getEncapsulatedObject();
    }

    /**
     * Method to check if an {@link APILayerMacaroon} is valid, given the macaroon secret.
     *
     * @param macaroonSecret The macaroon secret.
     * @return True if the macaroon is valid; false otherwise.
     */
    public boolean isValid(@NotNull String macaroonSecret) {
        var generatedSignature = publicIdentifier.generateSignature(macaroonSecret);
        if (!publicIdentifier.getSignature().equals(generatedSignature)) return false;

        generatedSignature = rTreePolicyMacaroonElement.generateSignature(generatedSignature);
        return rTreePolicyMacaroonElement.getSignature().equals(generatedSignature);
    }

    @Override
    public String toString() {
        return "APILayerMacaroon{" +
                "publicIdentifier=" + publicIdentifier +
                ", rTreePolicyMacaroonElement=" + rTreePolicyMacaroonElement +
                ", signature=" + signature + '}';
    }

    @Override
    public byte[] serialize() throws IOException {
        byte[] firstElementAsByteArray = ExportableUtils.serialize(publicIdentifier);
        byte[] secondElementAsByteArray = ExportableUtils.serialize(rTreePolicyMacaroonElement);
        byte[] signatureAsByteArray = signature.getBytes(StandardCharsets.UTF_8);

        ByteBuffer byteBuffer = ByteBuffer.allocate(2 * 4 + firstElementAsByteArray.length +
                secondElementAsByteArray.length + signatureAsByteArray.length);
        byteBuffer.putInt(firstElementAsByteArray.length);
        byteBuffer.put(firstElementAsByteArray);
        byteBuffer.putInt(secondElementAsByteArray.length);
        byteBuffer.put(secondElementAsByteArray);
        byteBuffer.put(signatureAsByteArray);

        return byteBuffer.array();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof APILayerMacaroon)) return false;

        APILayerMacaroon that = (APILayerMacaroon) o;

        if (!publicIdentifier.equals(that.publicIdentifier)) return false;
        if (!rTreePolicyMacaroonElement.equals(that.rTreePolicyMacaroonElement)) return false;
        return signature.equals(that.signature);
    }

    @Override
    public int hashCode() {
        int result = publicIdentifier.hashCode();
        result = 31 * result + rTreePolicyMacaroonElement.hashCode();
        result = 31 * result + signature.hashCode();
        return result;
    }
}
