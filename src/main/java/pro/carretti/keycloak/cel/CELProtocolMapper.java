package pro.carretti.keycloak.cel;

import com.google.auto.service.AutoService;
import com.google.common.collect.ImmutableMap;

import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.common.CelValidationException;
import dev.cel.runtime.CelEvaluationException;
import dev.cel.runtime.CelRuntime;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jboss.logging.Logger;

import org.keycloak.Config;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;

import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

@AutoService(ProtocolMapper.class)
public class CELProtocolMapper extends AbstractCELProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    public static final String PROVIDER_ID = "cel-mapper";

    private static final Logger LOG = Logger.getLogger(CELProtocolMapper.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("expression");
        property.setLabel("Expression");
        property.setHelpText("CEL expression to be evaluated and mapped into the corresponding claim(s)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, CELProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "CEL Expression";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
    }

    @Override
    public String getHelpText() {
        return "Map a CEL expression to a token claim";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        Map<String, String> config = mappingModel.getConfig();
        String expression = config.get("expression");
        LOG.info(expression);

        try {
            // Compile the expression into an Abstract Syntax Tree.
            CelAbstractSyntaxTree ast = cel.compile(expression).getAst();
            // Plan the program
            CelRuntime.Program program = cel.createProgram(ast);

            var val = program.eval(ImmutableMap.of(
                    "userSession", wrap(userSession),
                    "user", wrap(userSession.getUser()),
                    "clientSession", wrap(clientSessionCtx.getClientSession())
                )
            );
            LOG.info(val);
            token.setOtherClaims(config.get(TOKEN_CLAIM_NAME), val);
        } catch (CelEvaluationException e) {
            LOG.errorv(e, "Error evaluating expression: {0}", expression);
        } catch (CelValidationException e) {
            LOG.errorv(e, "Error validating expression: {0}", expression);
        }

    }

}
