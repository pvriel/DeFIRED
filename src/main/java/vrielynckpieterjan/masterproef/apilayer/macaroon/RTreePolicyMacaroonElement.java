package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.PolicyRight;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Class representing a {@link MacaroonElement} which encapsulates an {@link RTreePolicy} instance.
 */
public class RTreePolicyMacaroonElement extends MacaroonElement<RTreePolicy> {

    /**
     * Constructor for the {@link RTreePolicyMacaroonElement} class.
     * @param   previousElement
     *          The previous {@link MacaroonElement} of the {@link APILayerMacaroon}.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    public RTreePolicyMacaroonElement(@NotNull MacaroonElement previousElement, @NotNull RTreePolicy encapsulatedObject) {
        super(previousElement, encapsulatedObject);
    }

    protected RTreePolicyMacaroonElement(@NotNull String signature, @NotNull RTreePolicy encapsulatedObject) {
        super(signature, encapsulatedObject, false);
    }

    @Override
    public String toString() {
        return getEncapsulatedObject().toString();
    }

    @Override
    public byte[] serialize() throws IOException {
        byte[] encapsulatedObjectAsByteArray = ExportableUtils.serialize(getEncapsulatedObject());
        byte[] signatureAsByteArray = getSignature().getBytes(StandardCharsets.UTF_8);

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + encapsulatedObjectAsByteArray.length + signatureAsByteArray.length);
        byteBuffer.putInt(encapsulatedObjectAsByteArray.length);
        byteBuffer.put(encapsulatedObjectAsByteArray);
        byteBuffer.put(signatureAsByteArray);

        return byteBuffer.array();
    }

    @NotNull
    public static RTreePolicyMacaroonElement deserialize(@NotNull ByteBuffer byteBuffer) throws IOException {
        byte[] encapsulatedObjectAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(encapsulatedObjectAsByteArray);
        RTreePolicy encapsulatedObject = ExportableUtils.deserialize(encapsulatedObjectAsByteArray, RTreePolicy.class);

        byte[] signatureAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(signatureAsByteArray);
        String signature = new String(signatureAsByteArray, StandardCharsets.UTF_8);

        return new RTreePolicyMacaroonElement(signature, encapsulatedObject);
    }
}
