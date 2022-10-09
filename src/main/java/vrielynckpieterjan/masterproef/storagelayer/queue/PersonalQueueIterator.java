package vrielynckpieterjan.masterproef.storagelayer.queue;

import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;

import java.io.IOException;

/**
 * Interface representing an iterator, which can be used to iterate over the personal queue of a user of the framework.
 */
@FunctionalInterface
public interface PersonalQueueIterator {

    /**
     * Getter for the next {@link Attestation} or {@link vrielynckpieterjan.masterproef.applicationlayer.attestation.NamespaceAttestation}
     * in the personal queue of the user.
     *
     * @return The next {@link Attestation}.
     * @throws IOException              If an IO-related exception occurred in the {@link StorageLayer}.
     * @throws IllegalArgumentException If no next {@link Attestation}s were found.
     */
    @NotNull Attestation next() throws IOException, IllegalArgumentException;
}
