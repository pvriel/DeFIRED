package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.logging.Logger;

class TCPReflectionMethodInvocationServer extends ReflectionMethodInvocationServer {

    private final static Logger logger = Logger.getLogger(TCPReflectionMethodInvocationServer.class.getName());

    private final ServerSocket serverSocket;

    protected TCPReflectionMethodInvocationServer(int amountOfThreads, int port) throws IOException {
        super(amountOfThreads);
        serverSocket = new ServerSocket(port);
    }

    @Override
    public void run() {
        logger.info(String.format("TCPReflectionMethodInvocationServer (%s) running on address (%s).",
                this, serverSocket.getLocalSocketAddress()));
        super.run();
    }

    @Override
    @NotNull ReflectionMethodInvocationServerRequest receiveRequest() throws IOException {
        var socket = serverSocket.accept();

        IOException thrownException = null;
        try {
            var inputStream = socket.getInputStream();
            var objectInputStream = new ObjectInputStream(inputStream);
            var object = objectInputStream.readObject();
            if (!(object instanceof ReflectionMethodInvocationServerRequest))
                throw new IOException("Received object is not a ReflectionMethodInvocationServerRequest.");

            var request = (ReflectionMethodInvocationServerRequest) object;
            return new TCPReflectionMethodInvocationServerRequest(request, socket);

        } catch (Exception e) {
            thrownException = new IOException(e);
        }

        try {
            socket.close();
        } catch (IOException ignored) {}

        throw thrownException;
    }

    public InetAddress getAddress() {
        return serverSocket.getInetAddress();
    }
}
