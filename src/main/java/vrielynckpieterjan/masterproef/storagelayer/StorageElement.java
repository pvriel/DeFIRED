package vrielynckpieterjan.masterproef.storagelayer;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;

import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;

/**
 * Abstract class representing an element which can be stored within the {@link StorageLayer} of the decentralized
 * access policy framework.
 */
public abstract class StorageElement implements Exportable {

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

    @Override
    public byte[] serialize() throws IOException {
        return identifier.serialize();
    }
}
