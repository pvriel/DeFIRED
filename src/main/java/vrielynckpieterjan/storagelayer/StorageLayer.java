package vrielynckpieterjan.storagelayer;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.encryptionlayer.entities.PublicEntityIdentifier;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * Interface representing the storage layer of the decentralized access policy framework.
 * The storage layer is realized using a multi-value distributed hash table.
 * The {@link StorageElement}s in that DHT are identified using {@link StorageElementIdentifier} instances.
 */
public interface StorageLayer {

    /**
     * Method to add a new {@link StorageElement} to the storage layer.
     * @param   newElement
     *          The new element.
     * @throws  IOException
     *          If an IO-related problem occurred.
     */
    void put(@NotNull StorageElement newElement) throws IOException;

    /**
     * Method to receive the {@link StorageElement}s, published using the given {@link StorageElementIdentifier}, as a set.
     * @param   identifier
     *          The identifier.
     * @throws  IOException
     *          If the {@link StorageLayer} could not be consulted, due to an IO-related problem.
     * @return  The {@link StorageElement}s.
     */
    Set<StorageElement> retrieve(@NotNull StorageElementIdentifier identifier) throws IOException;

    /**
     * Cf. retrieve(StorageElementIdentifier) method, with the only exception that
     * this method already filters the {@link StorageElement}s based on the given {@link Class} parameter.
     * @param   clazz
     *          The class of the subtype of the {@link StorageElement} class for which results should be returned.
     * @param   <T>
     *          The generic parameter.
     */
    default <T extends StorageElement> Set<T> retrieve(@NotNull StorageElementIdentifier identifier,
                                               @NotNull Class<T> clazz) throws IOException {
        Set<StorageElement> retrievedStorageElements = retrieve(identifier);

        Set<T> returnValue = new HashSet<>();
        for (StorageElement storageElement : retrievedStorageElements) {
            if (storageElement.getClass().equals(clazz)) returnValue.add((T) storageElement);
        }
        return returnValue;
    }
}
