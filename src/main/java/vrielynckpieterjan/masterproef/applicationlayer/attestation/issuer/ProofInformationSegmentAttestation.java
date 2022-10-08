package vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer;

import cryptid.ibe.domain.PrivateKey;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.AESCipherEncryptedSegment;
import vrielynckpieterjan.masterproef.shared.serialization.Exportable;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

/**
 * Class representing the proof information segment of the {@link IssuerPartAttestation}.
 */
public class ProofInformationSegmentAttestation implements Exportable {

    @NotNull
    private final Set<PrivateKey> privateKeysIBE;

    /**
     * Constructor for the {@link ProofInformationSegmentAttestation} class.
     *
     * @param privateKeysIBE The delegated {@link PrivateKey}s.
     */
    public ProofInformationSegmentAttestation(@NotNull Set<PrivateKey> privateKeysIBE) {
        this.privateKeysIBE = privateKeysIBE;
    }

    @NotNull
    public static ProofInformationSegmentAttestation deserialize(@NotNull ByteBuffer byteBuffer) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream;
        ObjectInputStream objectInputStream;
        int amountOfElements = byteBuffer.getInt();
        Set<PrivateKey> privateKeysIBE = new HashSet<>(amountOfElements);
        for (int i = 0; i < amountOfElements; i++) {
            int length = byteBuffer.getInt();
            byte[] privateKeyAsByteArray = new byte[length];
            byteBuffer.get(privateKeyAsByteArray);
            byteArrayInputStream = new ByteArrayInputStream(privateKeyAsByteArray);
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
            PrivateKey privateKey = (PrivateKey) objectInputStream.readObject();
            privateKeysIBE.add(privateKey);
        }
        return new ProofInformationSegmentAttestation(privateKeysIBE);
    }

    /**
     * Method to encrypt this {@link ProofInformationSegmentAttestation} instance using AES encryption.
     *
     * @param aesKey The AES key to encrypt this instance with.
     * @return The encrypted instance as a {@link AESCipherEncryptedSegment}.
     * @throws IllegalArgumentException If the provided AES key can't be used to encrypt this instance with.
     */
    public @NotNull AESCipherEncryptedSegment<ProofInformationSegmentAttestation> encrypt(@NotNull String aesKey)
            throws IllegalArgumentException {
        return new AESCipherEncryptedSegment<>(this, aesKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProofInformationSegmentAttestation)) return false;

        ProofInformationSegmentAttestation that = (ProofInformationSegmentAttestation) o;

        return getPrivateKeysIBE().equals(that.getPrivateKeysIBE());
    }

    @Override
    public int hashCode() {
        return getPrivateKeysIBE().hashCode();
    }

    /**
     * Getter for the IBE {@link PrivateKey}s of the issuer.
     *
     * @return The {@link PrivateKey}s.
     */
    @NotNull
    public Set<PrivateKey> getPrivateKeysIBE() {
        return privateKeysIBE;
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream;
        ObjectOutputStream objectOutputStream;
        int length = 4 + privateKeysIBE.size() * 4;
        byte[][] privateKeysAsByteArrays = new byte[privateKeysIBE.size()][];
        int i = 0;
        for (PrivateKey privateKey : privateKeysIBE) {
            byteArrayOutputStream = new ByteArrayOutputStream();
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(privateKey);
            privateKeysAsByteArrays[i] = byteArrayOutputStream.toByteArray();
            length += privateKeysAsByteArrays[i].length;
            i++;
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(length);
        byteBuffer.putInt(privateKeysIBE.size());
        for (i = 0; i < privateKeysAsByteArrays.length; i++) {
            byteBuffer.putInt(privateKeysAsByteArrays[i].length);
            byteBuffer.put(privateKeysAsByteArrays[i]);
        }

        return byteBuffer.array();
    }
}
