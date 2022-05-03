package vrielynckpieterjan.masterproef.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing a public {@link EntityIdentifier}.
 */
public class PublicEntityIdentifier
        extends EntityIdentifier<PrivateKey, PublicParameters> {


    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     *
     * @param rsaIdentifier                               The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     * @param   hashConcatenation
     *          Boolean indicating if the content of the namespaceServiceProviderEmailAddressUserConcatenation parameter
     *          should yet be hashed.
     */
    protected PublicEntityIdentifier(@NotNull PrivateKey rsaIdentifier, @NotNull PublicParameters ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation,
                                  boolean hashConcatenation) {
        super(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, hashConcatenation);
    }

    /**
     * Constructor for the {@link PublicEntityIdentifier} class.
     *
     * @param rsaIdentifier                               The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     *          This value should not be hashed yet.
     */
    public PublicEntityIdentifier(@NotNull PrivateKey rsaIdentifier, @NotNull PublicParameters ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        super(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, true);
    }

    @NotNull
    public static PublicEntityIdentifier deserialize(@NotNull ByteBuffer byteBuffer) throws IOException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        byte[] rsaIdentifierAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(rsaIdentifierAsByteArray);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(rsaIdentifierAsByteArray);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        PrivateKey rsaIdentifier = (PrivateKey) objectInputStream.readObject();

        byte[] ibeIdentifierAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(ibeIdentifierAsByteArray);
        byteArrayInputStream = new ByteArrayInputStream(ibeIdentifierAsByteArray);
        objectInputStream = new ObjectInputStream(byteArrayInputStream);
        PublicParameters ibeIdentifier = (PublicParameters) objectInputStream.readObject();

        byte[] namespaceServiceProviderEmailAddressUserConcatenationAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(namespaceServiceProviderEmailAddressUserConcatenationAsByteArray);
        String namespaceServiceProviderEmailAddressUserConcatenation = new String(namespaceServiceProviderEmailAddressUserConcatenationAsByteArray, StandardCharsets.UTF_8);
        return new PublicEntityIdentifier(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, false);
    }
}
