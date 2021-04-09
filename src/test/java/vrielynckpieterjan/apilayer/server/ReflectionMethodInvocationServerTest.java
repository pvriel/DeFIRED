package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ReflectionMethodInvocationServerTest {

    @Test
    void receiveRequest() {
        var server = new TestReflectionMethodInvocationServer();

        server.run();
        assertEquals("This is a test.", server.receivedOne.get());
        assertEquals(128, server.receivedTwo.get());
    }

    class TestReflectionMethodInvocationServer extends ReflectionMethodInvocationServer {

        private int indexRequest = 0;
        private final AtomicReference<String> receivedOne = new AtomicReference<>();
        private final AtomicInteger receivedTwo = new AtomicInteger();

        protected TestReflectionMethodInvocationServer() {
            super(10);
        }

        void testMethod(String argOne, Integer argTwo) {
            System.out.println("The test method is called!");
            receivedOne.set(argOne);
            receivedTwo.set(argTwo);
        }

        @Override
        synchronized @NotNull ReflectionMethodInvocationServerRequest receiveRequest() throws IOException {
            if (indexRequest != 0) {
                interrupt();
                throw new IOException("First request already handled.");
            }

            indexRequest ++;
            return new ReflectionMethodInvocationServerRequest("testMethod", "This is a test.",
                    128) {

                @Override
                void respond(@NotNull ReflectionMethodInvocationServerResponse response) {
                    System.out.println(String.format("Response: %s", response));
                }

                @Override
                public void close() { }
            };
        }
    }
}