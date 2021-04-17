package vrielynckpieterjan.masterproef.storagelayer;

import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.util.Objects;

/**
 * Class representing an identifier / pointer for a {@link StorageElement} in the {@link StorageLayer}.
 */
public class StorageElementIdentifier implements Serializable {

    private final String identifier;

    /**
     * Constructor for the {@link StorageElementIdentifier} class.
     * @param   identifier
     *          The actual value for the identifier of the {@link StorageElement}.
     */
    public StorageElementIdentifier(@NotNull String identifier) {
        this.identifier = identifier;
    }

    /**
     * Constructor for the {@link StorageElementIdentifier} class.
     * This constructor initializes a {@link StorageElementIdentifier} instance for the provided length.
     * @param   length
     *          The provided length.
     */
    public StorageElementIdentifier(int length) {
        this(RandomStringUtils.randomAlphanumeric(length));
    }

    /**
     * Constructor for the {@link StorageElementIdentifier} class.
     * This constructor initializes a {@link StorageElementIdentifier} instance of length 128.
     */
    public StorageElementIdentifier() {
        this(128);
    }

    /**
     * Getter for the identifier.
     * @return  The identifier.
     */
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StorageElementIdentifier that = (StorageElementIdentifier) o;
        return identifier.equals(that.identifier);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identifier);
    }

    @Override
    public String toString() {
        return "StorageElementIdentifier{" +
                "identifier='" + identifier + '\'' +
                '}';
    }
}
