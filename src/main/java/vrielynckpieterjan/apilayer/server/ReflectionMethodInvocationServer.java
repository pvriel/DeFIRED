package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

abstract class ReflectionMethodInvocationServer extends Thread {

    private final static Logger logger = Logger.getLogger(ReflectionMethodInvocationServer.class.getName());

    private final ExecutorService executorService;

    protected ReflectionMethodInvocationServer(int amountOfThreads) {
        executorService = Executors.newFixedThreadPool(amountOfThreads);
        setDaemon(false);
    }

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

        logger.info(String.format("ReflectionMethodInvocationServer (%s) interrupted; awaiting termination...", this));
        try {
            executorService.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) { e.printStackTrace();}
        logger.info(String.format("ReflectionMethodInvocationServer (%s) terminated.", this));
    }

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
        } catch (IOException ignored) { } // May already been closed; just ignore it.
    }
}
