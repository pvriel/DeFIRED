package vrielynckpieterjan.masterproef.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.Closeable;
import java.io.IOException;
import java.io.Serializable;

class ReflectionMethodInvocationServerRequest implements Closeable, Serializable {

    private final String invokedMethodName;
    private final Serializable[] parameters;

    protected ReflectionMethodInvocationServerRequest(@NotNull String methodName,
                                                      @NotNull Serializable... parameters) {
        invokedMethodName = methodName;
        this.parameters = parameters;
    }

    String getInvokedMethodName() {
        return invokedMethodName;
    }

    Class<?>[] getParameterTypesInvocation () throws ClassNotFoundException {
        Class<?>[] returnValue = new Class[parameters.length];
        for (int i = 0; i < parameters.length; i ++)
            returnValue[i] = parameters[i].getClass();

        return returnValue;
    }

    Serializable[] getParameters() {
        return parameters;
    }

    void respond(@NotNull ReflectionMethodInvocationServerResponse response) throws IOException {
        throw new IOException("Not implemented.");
    }

    @Override
    public void close() throws IOException { }
}
