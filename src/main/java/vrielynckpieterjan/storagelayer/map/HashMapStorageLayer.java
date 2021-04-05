package vrielynckpieterjan.storagelayer.map;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.storagelayer.StorageElement;
import vrielynckpieterjan.storagelayer.StorageElementIdentifier;
import vrielynckpieterjan.storagelayer.StorageLayer;

import java.util.*;

/**
 * Class representing a {@link HashMap} implementation of the {@link StorageLayer} interface.
 * @implSpec
 *              The decision was made to implement the {@link StorageLayer} with a {@link HashMap},
 *              since the used Kademlia library could not support the size of the {@link vrielynckpieterjan.applicationlayer.attestation.Attestation} instances.
 *              Since the multi-value DHT is considered a building block for this thesis,
 *              the decision was made to just replace it with a {@link HashMap}.
 *              TODO: maybe try to fix this?
 */
public class HashMapStorageLayer implements StorageLayer {

    private final static Map<StorageElementIdentifier, Set<StorageElement>> storedElements =
            Collections.synchronizedMap(new HashMap<>());

    @Override
    public void put(@NotNull StorageElement newElement) {
        if (!storedElements.containsKey(newElement.getStorageLayerIdentifier()))
            storedElements.put(newElement.getStorageLayerIdentifier(), Collections.synchronizedSet(new HashSet<>()));
        storedElements.get(newElement.getStorageLayerIdentifier()).add(newElement);
    }

    @Override
    public Set<StorageElement> retrieve(@NotNull StorageElementIdentifier identifier) {
        return storedElements.getOrDefault(identifier, new HashSet<>());
    }
}
