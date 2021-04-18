package vrielynckpieterjan.masterproef.apilayer.server;

import org.jetbrains.annotations.NotNull;

import java.io.Serializable;

/**
 * Class representing the response for a {@link ReflectionMethodInvocationServerRequest} instance.
 */
class ReflectionMethodInvocationServerResponse implements Serializable {

    private final Serializable response;

    /**
     * Constructor for the {@link ReflectionMethodInvocationServerResponse} class.
     * @param   response
     *          The response as a {@link Serializable}.
     */
    ReflectionMethodInvocationServerResponse(@NotNull Serializable response) {
        this.response = response;
    }

    /**
     * Getter for the response as a {@link Serializable}.
     * @return  The {@link Serializable}.
     */
    public Serializable getResponse() {
        return response;
    }
}
