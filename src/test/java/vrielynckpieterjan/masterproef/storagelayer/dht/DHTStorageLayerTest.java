package vrielynckpieterjan.masterproef.storagelayer.dht;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationCommitment;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationObject;
import vrielynckpieterjan.masterproef.applicationlayer.revocation.RevocationSecret;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.EntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PrivateEntityIdentifier;
import vrielynckpieterjan.masterproef.encryptionlayer.entities.PublicEntityIdentifier;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DHTStorageLayerTest {

    private final Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userOne =
            EntityIdentifier.generateEntityIdentifierPair("testOne");
    private final Pair<PrivateEntityIdentifier, PublicEntityIdentifier> userTwo =
            EntityIdentifier.generateEntityIdentifierPair("testTwo");

    private final DHTStorageLayer dhtStorageLayerOne = new DHTStorageLayer(userOne.getRight(), 5878);
    private final DHTStorageLayer getDhtStorageLayerTwo = new DHTStorageLayer(userTwo.getRight(), 5879, dhtStorageLayerOne);

    DHTStorageLayerTest() throws IOException {
    }

    @Test
    void retrieve() throws IOException, InterruptedException {
        var revocationSecret = new RevocationSecret();
        var revocationCommitment = new RevocationCommitment(revocationSecret);
        var revocationObject = new RevocationObject(revocationCommitment, revocationSecret);

        dhtStorageLayerOne.put(revocationObject);
        var retrieved = getDhtStorageLayerTwo.retrieve(revocationCommitment);
        assertEquals(1, retrieved.size());
        retrieved.forEach(storageElement -> assertEquals(revocationCommitment, storageElement.getStorageLayerIdentifier()));
    }
}