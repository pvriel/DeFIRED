package vrielynckpieterjan.masterproef.encryptionlayer.entities;

import cryptid.ibe.domain.PublicParameters;
import org.apache.commons.lang3.tuple.Pair;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Class representing a private {@link EntityIdentifier}.
 */
public class PrivateEntityIdentifier
        extends EntityIdentifier<PublicKey, Pair<PublicParameters, BigInteger>> {


    /**
     * Constructor for the {@link PrivateEntityIdentifier} class.
     *
     * @param rsaIdentifier                               The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     *          This value should not be hashed yet.
     */
    public PrivateEntityIdentifier(@NotNull PublicKey rsaIdentifier, @NotNull Pair<PublicParameters, BigInteger> ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation) {
        this(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, true);
    }

    /**
     * Constructor for the {@link PrivateEntityIdentifier} class.
     *
     * @param rsaIdentifier                               The {@link Key} used to represent the RSA part of the identifier.
     * @param ibeIdentifier                                         The IBE part of the identifier.
     * @param   namespaceServiceProviderEmailAddressUserConcatenation
     *          A concatenation of the namespace and the e-mail address of the user.
     * @param   hashConcatenation
     *          Boolean indicating if the content of the namespaceServiceProviderEmailAddressUserConcatenation parameter
     *          should yet be hashed.
     */
    protected PrivateEntityIdentifier(@NotNull PublicKey rsaIdentifier, @NotNull Pair<PublicParameters, BigInteger> ibeIdentifier, @NotNull String namespaceServiceProviderEmailAddressUserConcatenation,
                                   boolean hashConcatenation) {
        super(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, hashConcatenation);
    }

    @NotNull
    public static PrivateEntityIdentifier deserialize(@NotNull ByteBuffer byteBuffer) throws IOException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        byte[] rsaIdentifierAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(rsaIdentifierAsByteArray);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(rsaIdentifierAsByteArray);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        PublicKey rsaIdentifier = (PublicKey) objectInputStream.readObject();

        byte[] ibeIdentifierAsByteArray = new byte[byteBuffer.getInt()];
        byteBuffer.get(ibeIdentifierAsByteArray);
        byteArrayInputStream = new ByteArrayInputStream(ibeIdentifierAsByteArray);
        objectInputStream = new ObjectInputStream(byteArrayInputStream);
        Pair<PublicParameters, BigInteger> ibeIdentifier = (Pair<PublicParameters, BigInteger>) objectInputStream.readObject();

        byte[] namespaceServiceProviderEmailAddressUserConcatenationAsByteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(namespaceServiceProviderEmailAddressUserConcatenationAsByteArray);
        String namespaceServiceProviderEmailAddressUserConcatenation = new String(namespaceServiceProviderEmailAddressUserConcatenationAsByteArray, StandardCharsets.UTF_8);

        return new PrivateEntityIdentifier(rsaIdentifier, ibeIdentifier, namespaceServiceProviderEmailAddressUserConcatenation, false);
    }
}
