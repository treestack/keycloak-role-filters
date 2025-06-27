package de.scobees.auth.provider.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import static org.keycloak.models.utils.RoleUtils.getDeepUserRoleMappings;
import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;

public class RegexFilterRolesMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
    public static final String PROVIDER_ID = "regex-roles-mapper";
    private static final Logger LOG = Logger.getLogger(RegexFilterRolesMapper.class);
    private static final String REGEX_CONFIG_PROPERTY = "regex.roles";
    private static final String INVERT_CONFIG_PROPERTY = "regex.invert";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty whitelistProperty = new ProviderConfigProperty();
        whitelistProperty.setName(REGEX_CONFIG_PROPERTY);
        whitelistProperty.setDefaultValue("");
        whitelistProperty.setLabel("Whitelisted Roles Regular Expression");
        whitelistProperty.setType(ProviderConfigProperty.STRING_TYPE);
        whitelistProperty.setHelpText("Example: ^ROLE_.* includes all roles starting with ROLE_. Use standard Java regex syntax.");
        configProperties.add(whitelistProperty);

        ProviderConfigProperty invertMatch = new ProviderConfigProperty();
        invertMatch.setName(INVERT_CONFIG_PROPERTY);
        invertMatch.setLabel("Invert match");
        invertMatch.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        invertMatch.setHelpText("Include roles that do not match the regex");
        configProperties.add(invertMatch);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexFilterRolesMapper.class);
    }

    @SuppressWarnings({"ReassignedVariable", "unchecked"})
    static void putNestedClaim(Map<String, Object> claims, String dottedKey, Object value) {
        String[] parts = dottedKey.split("\\.");
        Map<String, Object> current = claims;
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            current = (Map<String, Object>) current.computeIfAbsent(part, k -> new HashMap<>());
        }
        current.put(parts[parts.length - 1], value);
    }

    @Override
    public String getDisplayCategory() {
        return "Token Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Whitelist by Regex Roles Mapper";
    }

    @Override
    public String getHelpText() {
        return "Filters user roles to include only roles that match a specified regular expression";
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        if (mapperModel == null || mapperModel.getConfig() == null) {
            return;
        }
        String regexConfig = mapperModel.getConfig().get(REGEX_CONFIG_PROPERTY);
        if (regexConfig != null && !regexConfig.isEmpty()) {
            try {
                Pattern.compile(regexConfig);
            } catch (PatternSyntaxException ex) {
                throw new ProtocolMapperConfigException("error", "{0}", ex.getMessage());
            }
        }
        super.validateConfig(session, realm, client, mapperModel);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final UserModel user = userSession.getUser();
        if (user == null) {
            return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
        }

        final String regexConfig = mappingModel.getConfig().get(REGEX_CONFIG_PROPERTY);
        final boolean invertConfig = mappingModel.getConfig().get(INVERT_CONFIG_PROPERTY).equals("true");
        final String tokenClaimName = mappingModel.getConfig().get(TOKEN_CLAIM_NAME);

        if (regexConfig != null && !regexConfig.isEmpty()) {
            final Pattern regex = Pattern.compile(regexConfig);

            final Set<String> whitelistedRoles = getDeepUserRoleMappings(user).stream()
                    .map(RoleModel::getName)
                    .filter(role -> invertConfig != regex.matcher(role).matches())
                    .collect(Collectors.toSet());

            LOG.debugf("Filtered roles for user %s: %s", userSession.getUser().getUsername(), whitelistedRoles);

            final Map<String, Object> claims = token.getOtherClaims();
            putNestedClaim(claims, tokenClaimName, whitelistedRoles);

            setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        }

        return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
    }
}
