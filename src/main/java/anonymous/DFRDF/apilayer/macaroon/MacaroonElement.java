package anonymous.DFRDF.apilayer.macaroon;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Abstract class representing an element within an {@link APILayerMacaroon}.
 * @param   <ObjectType>
 *          The encapsulated object type.
 */
abstract class MacaroonElement<ObjectType extends Serializable> implements Serializable {

    private final ObjectType encapsulatedObject;
    private final String signature;

    /**
     * Constructor for the {@link MacaroonElement} class.
     * @param   macaroonSecret
     *          The macaroon secret.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    protected MacaroonElement(@NotNull String macaroonSecret, @NotNull ObjectType encapsulatedObject) {
        this.encapsulatedObject = encapsulatedObject;
        signature = generateSignature(macaroonSecret);
    }

    /**
     * Constructor for the {@link MacaroonElement} class.
     * @param   previousElement
     *          The previous {@link MacaroonElement} of the {@link APILayerMacaroon}.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    protected MacaroonElement(@NotNull MacaroonElement previousElement, @NotNull ObjectType encapsulatedObject) {
        this(previousElement.getSignature(), encapsulatedObject);
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
    @NotNull String generateSignature(@NotNull String macaroonSecret) {
        byte[] serializedObject = SerializationUtils.serialize(encapsulatedObject);
        return new HmacUtils(HmacAlgorithms.HMAC_SHA_512, macaroonSecret).hmacHex(serializedObject);
    }
}
