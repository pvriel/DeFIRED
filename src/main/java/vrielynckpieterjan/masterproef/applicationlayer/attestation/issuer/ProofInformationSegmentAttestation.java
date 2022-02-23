package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import cryptid.ibe.domain.PrivateKey;
import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Set;

/**
 * Class representing the proof information segment of the {@link IssuerPartAttestation}.
 */
public class ProofInformationSegmentAttestation implements Serializable {

    @NotNull
    private final Set<PrivateKey> privateKeysIBE;

    /**
     * Constructor for the {@link ProofInformationSegmentAttestation} class.
     * @param   privateKeysIBE
     *          The delegated {@link PrivateKey}s.
     */
    public ProofInformationSegmentAttestation(@NotNull Set<PrivateKey> privateKeysIBE) {
        this.privateKeysIBE = privateKeysIBE;
    }

    /**
     * Method to encrypt this {@link ProofInformationSegmentAttestation} instance using AES encryption.
     * @param   aesKey
     *          The AES key to encrypt this instance with.
     * @return  The encrypted instance as a {@link AESCipherEncryptedSegment}.
     * @throws  IllegalArgumentException
     *          If the provided AES key can't be used to encrypt this instance with.
     */
    public @NotNull AESCipherEncryptedSegment<ProofInformationSegmentAttestation> encrypt(@NotNull String aesKey)
        throws IllegalArgumentException {
        return new AESCipherEncryptedSegment<>(this, aesKey);
    }

    /**
     * Getter for the IBE {@link PrivateKey}s of the issuer.
     * @return The {@link PrivateKey}s.
     */
    @NotNull
    public Set<PrivateKey> getPrivateKeysIBE() {
        return privateKeysIBE;
    }
}
