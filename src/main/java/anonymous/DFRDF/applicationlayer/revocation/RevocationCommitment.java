package anonymous.DFRDF.applicationlayer.revocation;

import anonymous.DFRDF.storagelayer.StorageElement;
import anonymous.DFRDF.storagelayer.StorageElementIdentifier;
import anonymous.DFRDF.storagelayer.StorageLayer;
import com.google.common.hash.Hashing;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;


/**
 * Class representing a revocation commitment,
 * which is a SHA-512 version of a {@link RevocationSecret}.
 * @implNote
 *          This class is implemented as a subclass of the {@link StorageElementIdentifier} class,
 *          due to the fact that {@link RevocationCommitment}s can also be used as identifiers
 *          for the {@link StorageLayer} to store {@link RevocationObject}s
 *          with.
 */
public class RevocationCommitment extends StorageElementIdentifier {


    /**
     * Constructor for the {@link RevocationCommitment} class.
     *
     * @param identifier The identifier of the {@link StorageElement}.
     */
    public RevocationCommitment(@NotNull String identifier) {
        super(identifier);
    }

    /**
     * Constructor for the {@link RevocationCommitment} class.
     * @param   revocationSecret
     *          The original {@link RevocationSecret}.
     */
    public RevocationCommitment(@NotNull RevocationSecret revocationSecret) {
        this(Hashing.sha512().hashString(revocationSecret.getSecret(), StandardCharsets.UTF_8).toString());
    }

    /**
     * Method to check if this {@link RevocationCommitment} is revealed in the {@link StorageLayer}.
     * @param   storageLayer
     *          The {@link StorageLayer}.
     * @return  True if the {@link RevocationCommitment} is revealed; false otherwise.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted due to an IO-related problem.
     */
    public boolean isRevealedInStorageLayer(@NotNull StorageLayer storageLayer) throws IOException {
        Set<RevocationObject> retrievedRevocationObjects = storageLayer.retrieve(this, RevocationObject.class);
        for (RevocationObject revocationObject : retrievedRevocationObjects) {
            if (revocationObject.isValid()) return true;
        }
        return false;
    }
}
