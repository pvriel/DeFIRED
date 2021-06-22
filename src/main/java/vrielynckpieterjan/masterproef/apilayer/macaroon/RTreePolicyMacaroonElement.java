package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;

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
