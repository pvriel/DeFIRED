package vrielynckpieterjan.masterproef.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.Closeable;
import java.io.IOException;
import java.io.Serializable;

/**
 * Class representing an incoming request, which can be handled by a {@link ReflectionMethodInvocationServer}.
 * The instances can be used to respond to the requests, by using the close() and
 * respond(ReflectionMethodInvocationServerResponse) methods.
 */
class ReflectionMethodInvocationServerRequest implements Closeable, Serializable {

    private final String invokedMethodName;
    private final Serializable[] parameters;

    /**
     * Constructor for the {@link ReflectionMethodInvocationServerRequest} class.
     *
     * @param methodName The name of the {@link java.lang.reflect.Method} this {@link ReflectionMethodInvocationServerRequest}
     *                   wants to invoke on the {@link ReflectionMethodInvocationServer} instance.
     * @param parameters The provided parameters to invoke the {@link java.lang.reflect.Method} with.
     */
    protected ReflectionMethodInvocationServerRequest(@NotNull String methodName,
                                                      @NotNull Serializable... parameters) {
        invokedMethodName = methodName;
        this.parameters = parameters;
    }

    /**
     * Getter for the name of the {@link java.lang.reflect.Method} this {@link ReflectionMethodInvocationServerRequest}
     * wants to invoke.
     *
     * @return The name of the method.
     */
    String getInvokedMethodName() {
        return invokedMethodName;
    }

    /**
     * Getter for the {@link Class}es of the provided parameters.
     *
     * @return The {@link Class}es.
     * @throws ClassNotFoundException If the {@link ReflectionMethodInvocationServerRequest} is invalid.
     */
    Class<?>[] getParameterTypesInvocation() throws ClassNotFoundException {
        Class<?>[] returnValue = new Class[parameters.length];
        for (int i = 0; i < parameters.length; i++)
            returnValue[i] = parameters[i].getClass();

        return returnValue;
    }

    /**
     * Getter for the provided arguments.
     *
     * @return The arguments.
     */
    Serializable[] getParameters() {
        return parameters;
    }

    /**
     * Method to respond to the request with a {@link ReflectionMethodInvocationServerResponse} instance.
     *
     * @param response The {@link ReflectionMethodInvocationServerResponse} instance.
     * @throws IOException If an IO-related exception occurred while responding to the request.
     */
    void respond(@NotNull ReflectionMethodInvocationServerResponse response) throws IOException {
        throw new IOException("Not implemented.");
    }

    @Override
    public void close() throws IOException {
    }
}
