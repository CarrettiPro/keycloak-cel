package pro.carretti.keycloak.cel;

import com.google.auto.service.AutoService;
import com.google.common.collect.ImmutableMap;


import dev.cel.common.CelAbstractSyntaxTree;
import dev.cel.policy.CelPolicy;
import dev.cel.policy.CelPolicyCompiler;
import dev.cel.policy.CelPolicyCompilerFactory;
import dev.cel.policy.CelPolicyParser;
import dev.cel.policy.CelPolicyParserFactory;
import dev.cel.policy.CelPolicyValidationException;
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
public class CELPolicyProtocolMapper extends AbstractCELProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    public static final String PROVIDER_ID = "cel-policy-mapper";

    private static final Logger LOG = Logger.getLogger(CELPolicyProtocolMapper.class);

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    private CelPolicyParser parser;
    private CelPolicyCompiler compiler;

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("expression");
        property.setLabel("CEL Policy");
        property.setHelpText("CEL policy to be evaluated and mapped into the corresponding claim(s)");
        property.setType(ProviderConfigProperty.SCRIPT_TYPE);
        property.setRequired(true);
        CONFIG_PROPERTIES.add(property);

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, CELPolicyProtocolMapper.class);
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "CEL Policy";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.parser = CelPolicyParserFactory.newYamlParserBuilder().build();
        this.compiler = CelPolicyCompilerFactory.newPolicyCompiler(cel).build();
    }

    @Override
    public String getHelpText() {
        return "Map a CEL policy to a token claim";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        LOG.info(clientSessionCtx.getClass());
        Map<String, String> config = mappingModel.getConfig();
        String source = config.get("expression");
        LOG.info(source);

        try {
            CelPolicy policy = parser.parse(source);
            // Compile the expression into an Abstract Syntax Tree.
            CelAbstractSyntaxTree ast = compiler.compile(policy);
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
            LOG.errorv(e, "Error evaluating CEL policy: {0}", source);
        } catch (CelPolicyValidationException e) {
            LOG.errorv(e, "Error validating CEL policy : {0}", source);
        }

    }

}
