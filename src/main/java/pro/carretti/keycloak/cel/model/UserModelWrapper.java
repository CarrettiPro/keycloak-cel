package pro.carretti.keycloak.cel.model;

import java.util.List;
import java.util.Map;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;

public class UserModelWrapper {

    private final UserModel user;

    public UserModelWrapper(UserModel user) {
        this.user = user;
    }

    public String getId() {
        return user.getId();
    }

    public String getFirstName() {
        return user.getFirstName();
    }

    public String getLastName() {
        return user.getLastName();
    }

    public String getEmail() {
        return user.getEmail();
    }

    public Map<String, List<String>> getAttributes() {
        System.out.println(user.getAttributes());
        return user.getAttributes();
    }

    public List<String> getGroups() {
        return user.getGroupsStream().map(GroupModel::getName).toList();
    }

}
