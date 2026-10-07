package pro.carretti.keycloak.cel.model;

import java.util.Map;
import org.keycloak.models.AuthenticatedClientSessionModel;

public class ClientSessionModelWrapper {

    private final AuthenticatedClientSessionModel clientSession;

    public ClientSessionModelWrapper(AuthenticatedClientSessionModel clientSession) {
        this.clientSession = clientSession;
    }

    public Map<String, String> getNotes() {
        return clientSession.getNotes();
    }

}
