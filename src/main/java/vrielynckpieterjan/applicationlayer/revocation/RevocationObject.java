package vrielynckpieterjan.applicationlayer.revocation;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;

/**
 * Class representing a {@link StorageElement} which encapsulates a revealed {@link RevocationSecret}.
 */
public class RevocationObject extends StorageElement {

    private final RevocationSecret revealedSecret;

    /**
     * Constructor for the {@link RevocationObject} class.
     *
     * @param identifier The {@link StorageElementIdentifier} for this {@link StorageElement}.
     * @param revealedSecret    The revealed {@link RevocationSecret}.
     */
    public RevocationObject(@NotNull StorageElementIdentifier identifier,
                            @NotNull RevocationSecret revealedSecret) {
        super(identifier);
        this.revealedSecret = revealedSecret;
    }

    /**
     * Getter for the revealed {@link RevocationSecret}.
     * @return  The revealed {@link RevocationSecret}.
     */
    public RevocationSecret getRevealedSecret() {
        return revealedSecret;
    }
}
