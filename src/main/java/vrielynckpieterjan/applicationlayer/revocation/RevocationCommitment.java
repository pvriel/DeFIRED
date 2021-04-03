package vrielynckpieterjan.applicationlayer.revocation;

import com.google.common.hash.Hashing;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Class representing a revocation commitment,
 * which is a SHA-512 version of a {@link RevocationSecret}.
 */
public class RevocationCommitment implements Serializable {

    private final String commitment;

    /**
     * Constructor for the {@link RevocationCommitment} class.
     * @param   revocationSecret
     *          The {@link RevocationSecret} to hash.
     */
    public RevocationCommitment(@NotNull RevocationSecret revocationSecret) {
        commitment = Hashing.sha512().hashString(revocationSecret.getSecret(), StandardCharsets.UTF_8).toString();
    }

    /**
     * Getter for the commitment.
     * @return  The commitment.
     */
    public String getCommitment() {
        return commitment;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RevocationCommitment that = (RevocationCommitment) o;
        return commitment.equals(that.commitment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitment);
    }
}
