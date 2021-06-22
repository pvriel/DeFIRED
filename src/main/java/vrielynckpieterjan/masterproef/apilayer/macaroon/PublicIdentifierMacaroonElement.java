package vrielynckpieterjan.masterproef.apilayer.macaroon;

import org.jetbrains.annotations.NotNull;

/**
 * Class representing a {@link MacaroonElement} which encapsulates a public identifier for an {@link APILayerMacaroon}.
 */
class PublicIdentifierMacaroonElement extends MacaroonElement<String> {

    /**
     * Constructor for the {@link PublicIdentifierMacaroonElement} class.
     * @param   macaroonSecret
     *          The macaroon secret.
     * @param   encapsulatedObject
     *          The encapsulated object.
     */
    public PublicIdentifierMacaroonElement(@NotNull String macaroonSecret, @NotNull String encapsulatedObject) {
        super(macaroonSecret, encapsulatedObject);
    }

    @Override
    public String toString() {
        return getEncapsulatedObject();
    }
}
