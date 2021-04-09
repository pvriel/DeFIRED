package vrielynckpieterjan.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

class ReflectionMethodInvocationServerResponse implements Serializable {

    private final Serializable response;

    ReflectionMethodInvocationServerResponse(@NotNull Serializable response) {
        this.response = response;
    }

    public Serializable getResponse() {
        return response;
    }
}
