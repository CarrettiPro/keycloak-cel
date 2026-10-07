package pro.carretti.keycloak.cel.model;

import java.util.Map;
import org.keycloak.models.UserSessionModel;

public class UserSessionModelWrapper {

    private final UserSessionModel session;

    public UserSessionModelWrapper(UserSessionModel session) {
        this.session = session;
    }

    public Map<String, String> getNotes() {
        return session.getNotes();
    };

}
