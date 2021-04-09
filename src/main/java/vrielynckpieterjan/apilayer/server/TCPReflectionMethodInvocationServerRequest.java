package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;

class TCPReflectionMethodInvocationServerRequest extends ReflectionMethodInvocationServerRequest {

    private final transient Socket socket;

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
