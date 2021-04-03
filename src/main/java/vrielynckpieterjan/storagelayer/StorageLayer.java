package vrielynckpieterjan.storagelayer;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.Set;

/**
 * Interface representing the storage layer of the decentralized access policy framework.
 * @param   <BootstrapObject>
 *          The type of objects which can be used for the bootstrap process.
 */
public interface StorageLayer<BootstrapObject> {

    /**
     * Method to bootstrap the storage layer, given an object to execute the bootstrap process with.
     * @param   bootstrapObject
     *          An object which is required to execute the bootstrap process.
     * @throws  IOException
     *          If the bootstrap process failed, due to an IO-related problem.
     */
    void bootstrap(@NotNull BootstrapObject bootstrapObject)
        throws IOException;

    /**
     * Method to add a new {@link StorageElement} to the storage layer.
     * @param   newElement
     *          The new element.
     * @throws  IOException
     *          If an IO-related problem occurred.
     */
    void put(@NotNull StorageElement newElement) throws IOException;


    /**
     * Method to receive the {@link StorageElement}s, published using the given identifier, as a set.
     * @param   identifier
     *          The identifier.
     * @return  The {@link StorageElement}s.
     */
    Set<StorageElement> retrieve(@NotNull StorageElementIdentifier identifier);
}
