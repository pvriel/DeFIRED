package vrielynckpieterjan.applicationlayer.revocation;

import com.google.common.hash.Hashing;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;

import java.nio.charset.StandardCharsets;

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
    public RevocationObject(@NotNull RevocationCommitment identifier,
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

    /**
     * Method to check if the revealed secret actually corresponds with the {@link RevocationCommitment}
     * which was used as {@link StorageElementIdentifier} for this {@link StorageElement}.
     * @return  True if the revealed secret actually corresponds with the {@link RevocationCommitment}
     *          used for the constructor of this instance; false otherwise.
     */
    public boolean isValid() {
        String reconstructedRevocationCommitment = Hashing.sha512().hashString(revealedSecret.getSecret(), StandardCharsets.UTF_8)
                .toString();
        return reconstructedRevocationCommitment.equals(getStorageLayerIdentifier().getIdentifier());
    }
}
