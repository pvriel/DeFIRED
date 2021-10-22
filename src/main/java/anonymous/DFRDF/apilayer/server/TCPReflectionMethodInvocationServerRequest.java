package anonymous.DFRDF.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;

/**
 * Class representing a TCP-related {@link ReflectionMethodInvocationServerRequest}.
 * The instances contain an additional transient {@link Socket} instance compared to the parent class,
 * which was added and is used by the {@link TCPReflectionMethodInvocationServer} class.
 */
class TCPReflectionMethodInvocationServerRequest extends ReflectionMethodInvocationServerRequest {

    private final transient Socket socket;

    /**
     * Constructor for the {@link TCPReflectionMethodInvocationServerRequest} class.
     * @param   originalRequest
     *          The originally received {@link ReflectionMethodInvocationServerRequest} instance to extend upon.
     * @param   socket
     *          The {@link Socket}.
     */
    protected TCPReflectionMethodInvocationServerRequest(@NotNull ReflectionMethodInvocationServerRequest originalRequest,
                                                         @NotNull Socket socket) {
        super(originalRequest.getInvokedMethodName(), originalRequest.getParameters());
        this.socket = socket;
    }

    @Override
    void respond(@NotNull ReflectionMethodInvocationServerResponse response) throws IOException {
        var outputStream = socket.getOutputStream();
        var objectOutputStream = new ObjectOutputStream(outputStream);
        objectOutputStream.writeObject(response);
        objectOutputStream.close();
        outputStream.close();
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
