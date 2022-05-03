package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Class representing a {@link MacaroonElement} which encapsulates a public identifier for an {@link APILayerMacaroon}.
 */
public class PublicIdentifierMacaroonElement extends MacaroonElement<String> {

    /**
     * Constructor for the {@link PublicIdentifierMacaroonElement} class.
     * @param   macaroonSecret
     *          The macaroon secret.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    public PublicIdentifierMacaroonElement(@NotNull String macaroonSecret, @NotNull String encapsulatedObject) {
        this(macaroonSecret, encapsulatedObject, true);
    }

    protected PublicIdentifierMacaroonElement(@NotNull String secretOrSignature, @NotNull String encapsulatedObject, boolean generateSignature) {
        super(secretOrSignature, encapsulatedObject, generateSignature);
    }

    @Override
    public String toString() {
        return getEncapsulatedObject();
    }

    @Override
    public byte[] serialize() throws IOException {
        byte[] encapsulatedObjectAsByteArray = getEncapsulatedObject().getBytes(StandardCharsets.UTF_8);
        byte[] signatureAsByteArray = getSignature().getBytes(StandardCharsets.UTF_8);

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + encapsulatedObjectAsByteArray.length + signatureAsByteArray.length);
        byteBuffer.putInt(encapsulatedObjectAsByteArray.length);
        byteBuffer.put(encapsulatedObjectAsByteArray);
        byteBuffer.put(signatureAsByteArray);

        return byteBuffer.array();
    }

    @NotNull
    public static PublicIdentifierMacaroonElement deserialize(@NotNull ByteBuffer byteBuffer) {
        byte[] encapsulatedObjectAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(encapsulatedObjectAsByteArray);
        String encapsulatedObject = new String(encapsulatedObjectAsByteArray, StandardCharsets.UTF_8);

        byte[] signatureAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(signatureAsByteArray);
        String signature = new String(signatureAsByteArray, StandardCharsets.UTF_8);

        return new PublicIdentifierMacaroonElement(signature, encapsulatedObject, false);
    }
}
