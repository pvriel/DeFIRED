package vrielynckpieterjan.masterproef.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

/**
 * Abstract class representing a server, of which the methods can be invoked externally
 * in a reflection-oriented manner.
 */
abstract class ReflectionMethodInvocationServer extends Thread {

    private final static Logger logger = Logger.getLogger(ReflectionMethodInvocationServer.class.getName());

    private final ExecutorService executorService;

    /**
     * Constructor for the {@link ReflectionMethodInvocationServer} class.
     *
     * @param amountOfThreads The amount of simultaneous requests this {@link ReflectionMethodInvocationServer} instance can handle.
     */
    protected ReflectionMethodInvocationServer(int amountOfThreads) {
        executorService = Executors.newFixedThreadPool(amountOfThreads);
        setDaemon(false);
    }

    /**
     * Method to receive the next {@link ReflectionMethodInvocationServerRequest} instance to handle for this server.
     *
     * @return The {@link ReflectionMethodInvocationServerRequest}.
     * @throws IOException If an IO-related problem occurred.
     */
    abstract @NotNull ReflectionMethodInvocationServerRequest receiveRequest() throws IOException;

    @Override
    public void run() {
        logger.info(String.format("ReflectionMethodInvocationServer (%s) is running.", this));
        while (!isInterrupted()) {
            try {
                var receivedRequest = receiveRequest();
                executorService.submit(() -> handleNextRequest(receivedRequest));
            } catch (IOException e) {
                logger.warning(String.format("An IOException occurred while trying to handle" +
                        " the next request for ReflectionMethodInvocationServer (%s) (reason: %s).", this, e));
            }
        }

        logger.info(String.format("ReflectionMethodInvocationServer (%s) interrupted; awaiting shutdown...", this));
        executorService.shutdown();
        logger.info(String.format("ReflectionMethodInvocationServer (%s) shut down.", this));
    }

    /**
     * Method to handle a received {@link ReflectionMethodInvocationServerRequest} instance.
     *
     * @param request The received request.
     */
    private void handleNextRequest(@NotNull ReflectionMethodInvocationServerRequest request) {
        try {
            var method = this.getClass().getDeclaredMethod(request.getInvokedMethodName(), request.getParameterTypesInvocation());
            var result = method.invoke(this, (Object[]) request.getParameters());
            if (result != null && result instanceof ReflectionMethodInvocationServerResponse)
                request.respond((ReflectionMethodInvocationServerResponse) result);
            else
                logger.severe(String.format("The %s Method was successfully invoked, but the Method" +
                        " returned (%s) while a ReflectionMethodInvocationServerResponse instance" +
                        " was expected.", method, result));

        } catch (Exception e) {
            logger.warning(String.format("Could not handle ReflectionMethodInvocationServerRequest (%s)" +
                    " (reason: %s).", request, e));
        }

        try {
            request.close();
        } catch (IOException ignored) {
        } // May already been closed; just ignore it.
    }
}
