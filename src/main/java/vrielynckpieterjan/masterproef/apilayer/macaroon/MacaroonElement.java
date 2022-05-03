package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;

import java.io.Serializable;

/**
 * Abstract class representing an element within an {@link APILayerMacaroon}.
 * @param   <ObjectType>
 *          The encapsulated object type.
 */
abstract class MacaroonElement<ObjectType extends Serializable> implements Exportable {

    private final ObjectType encapsulatedObject;
    private final String signature;

    /**
     * Constructor for the {@link MacaroonElement} class.
     * @param   secretOrSignature
     *          The macaroon secret or its signature.
     * @param   encapsulatedObject
     *          The encapsulated object in the macaroon element.
     */
    protected MacaroonElement(@NotNull String secretOrSignature, @NotNull ObjectType encapsulatedObject, boolean generateSignature) {
        this.encapsulatedObject = encapsulatedObject;
        signature = (generateSignature)? generateSignature(secretOrSignature) : secretOrSignature;
    }

    /**
     * Constructor for the {@link MacaroonElement} class.
     * @param   previousElement
     *          The previous {@link MacaroonElement} of the {@link APILayerMacaroon}.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    protected MacaroonElement(@NotNull MacaroonElement previousElement, @NotNull ObjectType encapsulatedObject) {
        this(previousElement.getSignature(), encapsulatedObject, true);
    }

    /**
     * Getter for the encapsulated object.
     * @return  The encapsulated object.
     */
    public ObjectType getEncapsulatedObject() {
        return encapsulatedObject;
    }

    /**
     * Getter for the signature of the {@link MacaroonElement}.
     * @return  The signature.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Method to generate the signature of the {@link MacaroonElement}.
     * @param   macaroonSecret
     *          The macaroon secret, or the signature of the previous {@link MacaroonElement}
     *          within the {@link APILayerMacaroon}.
     * @return  The signature.
     */
    protected @NotNull String generateSignature(@NotNull String macaroonSecret) {
        byte[] serializedObject = SerializationUtils.serialize(encapsulatedObject);
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_512, macaroonSecret).hmacHex(serializedObject);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MacaroonElement)) return false;

        MacaroonElement<?> that = (MacaroonElement<?>) o;

        if (!getEncapsulatedObject().equals(that.getEncapsulatedObject())) return false;
        return getSignature().equals(that.getSignature());
    }

    @Override
    public int hashCode() {
        int result = getEncapsulatedObject().hashCode();
        result = 31 * result + getSignature().hashCode();
        return result;
    }
}
