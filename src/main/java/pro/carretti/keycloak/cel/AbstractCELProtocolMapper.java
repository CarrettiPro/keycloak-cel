package pro.carretti.keycloak.cel;

import dev.cel.bundle.Cel;
import dev.cel.bundle.CelFactory;
import dev.cel.common.types.SimpleType;
import dev.cel.extensions.CelExtensions;
import dev.cel.parser.CelStandardMacro;
import org.keycloak.Config;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.representations.AddressClaimSet;
import pro.carretti.keycloak.cel.model.ClientSessionModelWrapper;
import pro.carretti.keycloak.cel.model.UserModelWrapper;
import pro.carretti.keycloak.cel.model.UserSessionModelWrapper;

public abstract class AbstractCELProtocolMapper extends AbstractOIDCProtocolMapper {

    protected static final Class[] CEL_TYPES = {
        // Cannot use interfaces here (yet) - see https://github.com/google/cel-java/issues/1061
//        UserSessionModel.class,
//        UserSessionAdapter.class
        ClientSessionModelWrapper.class,
        UserModelWrapper.class,
        UserSessionModelWrapper.class,
        AddressClaimSet.class,
    };

    protected Cel cel;

    @Override
    public void init(Config.Scope config) {
        this.cel = CelFactory.plannerCelBuilder()
                .addVar("user", SimpleType.ANY)
                .addVar("userSession", SimpleType.ANY)
                .addVar("clientSession", SimpleType.ANY)
                .addCompilerLibraries(CelExtensions.nativeTypes(CEL_TYPES), CelExtensions.strings(), CelExtensions.optional())
                .addRuntimeLibraries(CelExtensions.nativeTypes(CEL_TYPES), CelExtensions.strings(), CelExtensions.optional())
                .setStandardMacros(CelStandardMacro.STANDARD_MACROS)
                .build();
    }

    protected UserModelWrapper wrap(UserModel user) {
        return new UserModelWrapper(user);
    }

    protected UserSessionModelWrapper wrap(UserSessionModel userSession) {
        return new UserSessionModelWrapper(userSession);
    }

    protected ClientSessionModelWrapper wrap(AuthenticatedClientSessionModel clientSession) {
        return new ClientSessionModelWrapper(clientSession);
    }

}
