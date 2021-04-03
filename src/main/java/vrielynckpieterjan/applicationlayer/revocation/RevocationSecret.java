package vrielynckpieterjan.applicationlayer.revocation;

import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * Class representing a revocation secret.
 */
public class RevocationSecret {

    private final static int LENGTH_GENERATED_REVOCATION_SECRETS = 512;

    private final String secret;

    /**
     * Constructor for the {@link RevocationSecret} class.
     * @param   secret
     *          The used secret.
     */
    public RevocationSecret(@NotNull String secret) {
        this.secret = secret;
    }

    /**
     * Constructor for the {@link RevocationSecret} class.
     * The secret is randomly generated with length LENGTH_GENERATED_REVOCATION_SECRETS.
     */
    public RevocationSecret() {
        this(RandomStringUtils.randomAlphanumeric(LENGTH_GENERATED_REVOCATION_SECRETS));
    }

    /**
     * Getter for the secret.
     * @return  The secret.
     */
    public String getSecret() {
        return secret;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RevocationSecret that = (RevocationSecret) o;
        return secret.equals(that.secret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(secret);
    }
}
