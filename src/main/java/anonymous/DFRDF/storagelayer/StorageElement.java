package anonymous.DFRDF.storagelayer;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Abstract class representing an element which can be stored within the {@link StorageLayer} of the decentralized
 * access policy framework.
 */
public abstract class StorageElement implements Serializable {

    private final StorageElementIdentifier identifier;

    /**
     * Constructor for the {@link StorageElement} class.
     * @param   identifier
     *          The {@link StorageElementIdentifier} for this {@link StorageElement}.
     */
    public StorageElement(@NotNull StorageElementIdentifier identifier) {
        this.identifier = identifier;
    }

    /**
     * Getter for the {@link StorageElementIdentifier}.
     * @return  The {@link StorageElementIdentifier}.
     */
    public StorageElementIdentifier getStorageLayerIdentifier() {
        return identifier;
    }
}
