package anonymous.DFRDF.apilayer.macaroon;

import anonymous.DFRDF.applicationlayer.attestation.policy.RTreePolicy;
import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link MacaroonElement} which encapsulates an {@link RTreePolicy} instance.
 */
class RTreePolicyMacaroonElement extends MacaroonElement<RTreePolicy> {

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

    @Override
    public String toString() {
        return getEncapsulatedObject().toString();
    }
}
