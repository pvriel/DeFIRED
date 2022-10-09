package vrielynckpieterjan.masterproef.applicationlayer.proof;


import cryptid.ibe.domain.PrivateKey;
import org.jetbrains.annotations.NotNull;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.Attestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.AESEncryptionInformationSegmentAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.issuer.IssuerPartAttestation;
import vrielynckpieterjan.masterproef.applicationlayer.attestation.policy.RTreePolicy;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.schemes.IBEDecryptableSegment;
import vrielynckpieterjan.masterproef.shared.serialization.ExportableUtils;
import vrielynckpieterjan.masterproef.storagelayer.StorageLayer;
import vrielynckpieterjan.masterproef.storagelayer.queue.PersonalQueueIterator;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Class representing a disproof {@link AbstractProofObject}.
 */
public class DisproofObject extends AbstractProofObject {

    @NotNull
    private final static Random random = new Random();

    @NotNull
    private final Map<RTreePolicy, PrivateKey> includedPrivateKeys;
    @NotNull
    private final PublicEntityIdentifier publicEntityIdentifierOfProver;

    /**
     * Constructor for the {@link DisproofObject} class.
     *
     * @param publicEntityIdentifierOfProver The {@link PublicEntityIdentifier} of the prover.
     * @param privateEntityIdentifierProver  The {@link PrivateEntityIdentifier} of the prover.
     * @param policyToDisprove               The {@link RTreePolicy} that the prover wants to disprove.
     */
    public DisproofObject(@NotNull PublicEntityIdentifier publicEntityIdentifierOfProver,
                          @NotNull PrivateEntityIdentifier privateEntityIdentifierProver,
                          @NotNull RTreePolicy policyToDisprove) {
        this.publicEntityIdentifierOfProver = publicEntityIdentifierOfProver;

        this.includedPrivateKeys = new HashMap<>();
        policyToDisprove.generateRTreePolicyVariations().forEach(rTreePolicy ->
                includedPrivateKeys.put(rTreePolicy, IBEDecryptableSegment.generatePrivateKey(privateEntityIdentifierProver, rTreePolicy.toString())));
    }

    /**
     * Constructor for the {@link DisproofObject} class.
     *
     * @param includedPrivateKeys            The included private keys.
     * @param publicEntityIdentifierOfProver The public entity identifier of the prover.
     */
    protected DisproofObject(@NotNull Map<RTreePolicy, PrivateKey> includedPrivateKeys,
                             @NotNull PublicEntityIdentifier publicEntityIdentifierOfProver) {
        this.includedPrivateKeys = includedPrivateKeys;
        this.publicEntityIdentifierOfProver = publicEntityIdentifierOfProver;
    }

    @NotNull
    public static DisproofObject deserialize(@NotNull ByteBuffer byteBuffer) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream;
        ObjectInputStream objectInputStream;

        Map<RTreePolicy, PrivateKey> includedPrivateKeys = new HashMap<>();
        int amountOfIterations = byteBuffer.getInt();
        for (int i = 0; i < amountOfIterations; i++) {
            byte[] rTreePolicyAsByteArray = new byte[byteBuffer.getInt()];
            byteBuffer.get(rTreePolicyAsByteArray);
            RTreePolicy rTreePolicy = ExportableUtils.deserialize(rTreePolicyAsByteArray, RTreePolicy.class);

            byte[] privateKeyAsByteArray = new byte[byteBuffer.getInt()];
            byteBuffer.get(privateKeyAsByteArray);
            byteArrayInputStream = new ByteArrayInputStream(privateKeyAsByteArray);
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
            PrivateKey privateKey = (PrivateKey) objectInputStream.readObject();

            includedPrivateKeys.put(rTreePolicy, privateKey);
        }

        byte[] publicEntityIdentifierOfProverAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(publicEntityIdentifierOfProverAsByteArray);
        PublicEntityIdentifier publicEntityIdentifierOfProver = ExportableUtils.deserialize(publicEntityIdentifierOfProverAsByteArray, PublicEntityIdentifier.class);

        return new DisproofObject(includedPrivateKeys, publicEntityIdentifierOfProver);
    }

    /**
     * Method to check the validity of the {@link DisproofObject}.
     *
     * @param storageLayer A {@link StorageLayer} realization.
     * @throws IllegalStateException If this {@link DisproofObject} is not valid.
     */
    public void verify(@NotNull StorageLayer storageLayer) throws IllegalStateException {
        verifyIncludedPrivateKeys();
        verifyPersonalQueueVerifier(storageLayer);
    }

    private void verifyIncludedPrivateKeys() throws IllegalStateException {
        byte[] randomValue = new byte[128];
        random.nextBytes(randomValue);

        IBEDecryptableSegment<byte[]> encryptedRandomValue;
        byte[] decrypted;
        for (RTreePolicy includedPolicy : includedPrivateKeys.keySet()) {
            try {
                encryptedRandomValue = new IBEDecryptableSegment<>(randomValue, publicEntityIdentifierOfProver, includedPolicy);
                decrypted = encryptedRandomValue.decrypt(publicEntityIdentifierOfProver.getIBEIdentifier(), includedPrivateKeys.get(includedPolicy));
                if (!Arrays.equals(randomValue, decrypted)) throw new IllegalStateException(String.format(
                        "Invalid key given for RTreePolicy (%s).", includedPolicy));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private void verifyPersonalQueueVerifier(@NotNull StorageLayer storageLayer) throws IllegalStateException {
        try {
            PersonalQueueIterator personalQueueIteratorProver = storageLayer.getPersonalQueueUser(publicEntityIdentifierOfProver);
            Exception thrownException = null;
            Attestation foundAttestation;
            IssuerPartAttestation issuerPartAttestation;
            IBEDecryptableSegment<AESEncryptionInformationSegmentAttestation> ibeDecryptableSegment;
            try {
                do {
                    foundAttestation = personalQueueIteratorProver.next();
                    issuerPartAttestation = foundAttestation.getFirstLayer();
                    ibeDecryptableSegment = issuerPartAttestation.getAesEncryptionInformationSegment();
                    for (Map.Entry<RTreePolicy, PrivateKey> includedPolicyAndPrivateKey : includedPrivateKeys.entrySet()) {
                        try {
                            ibeDecryptableSegment.decrypt(publicEntityIdentifierOfProver.getIBEIdentifier(), includedPolicyAndPrivateKey.getValue());
                            // DisproofObject is not valid from here on.
                            thrownException = new IllegalStateException(String.format(
                                    "Attestation (%s) decrypted with (%s, %s).", foundAttestation, includedPolicyAndPrivateKey.getKey(),
                                    includedPolicyAndPrivateKey.getValue()));
                            break;
                        } catch (Exception ignored) {
                        }
                    }

                } while (thrownException == null);
            } catch (Exception ignored) {
            } // If end of personal queue is reached.

            if (thrownException != null) throw thrownException;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DisproofObject)) return false;

        DisproofObject that = (DisproofObject) o;

        if (!includedPrivateKeys.equals(that.includedPrivateKeys)) return false;
        return publicEntityIdentifierOfProver.equals(that.publicEntityIdentifierOfProver);
    }

    @Override
    public int hashCode() {
        int result = includedPrivateKeys.hashCode();
        result = 31 * result + publicEntityIdentifierOfProver.hashCode();
        return result;
    }

    @Override
    public byte[] serialize() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream;
        ObjectOutputStream objectOutputStream;
        int length = 4 + 2 * includedPrivateKeys.size() * 4;
        byte[][] serializedRTreePolicies = new byte[includedPrivateKeys.size()][];
        byte[][] serializedPrivateKeys = new byte[includedPrivateKeys.size()][];
        int i = 0;
        for (Map.Entry<RTreePolicy, PrivateKey> entry : includedPrivateKeys.entrySet()) {
            serializedRTreePolicies[i] = ExportableUtils.serialize(entry.getKey());
            byteArrayOutputStream = new ByteArrayOutputStream();
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(entry.getValue());
            serializedPrivateKeys[i] = byteArrayOutputStream.toByteArray();
            length += serializedRTreePolicies[i].length + serializedPrivateKeys[i].length;
            i++;
        }
        byte[] serializedPublicEntityIdentifierOfProver = ExportableUtils.serialize(publicEntityIdentifierOfProver);
        length += serializedPublicEntityIdentifierOfProver.length;

        ByteBuffer byteBuffer = ByteBuffer.allocate(length);
        byteBuffer.putInt(includedPrivateKeys.size());
        for (i = 0; i < serializedRTreePolicies.length; i++) {
            byteBuffer.putInt(serializedRTreePolicies[i].length);
            byteBuffer.put(serializedRTreePolicies[i]);
            byteBuffer.putInt(serializedPrivateKeys[i].length);
            byteBuffer.put(serializedPrivateKeys[i]);
        }
        byteBuffer.put(serializedPublicEntityIdentifierOfProver);

        return byteBuffer.array();
    }
}
