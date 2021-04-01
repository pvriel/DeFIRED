package vrielynckpieterjan.storagelayer;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Abstract class representing an element which can be stored within the storage layer of the decentralized
 * access policy framework.
 */
public abstract class StorageElement implements Serializable {

    private final String identifier;

    public StorageElement(@NotNull String identifier) {
        this.identifier = identifier;
    }

    public String getStorageLayerIdentifier() {
        return identifier;
    }
}
