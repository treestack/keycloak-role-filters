package de.treestack.auth.provider.mapper;

import org.jboss.logging.Logger;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.keycloak.models.utils.RoleUtils.getDeepUserRoleMappings;
import static org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

/**
 * A Keycloak protocol mapper that filters user roles based on a regular expression.
 * It can be used to include only roles that match a specified regex pattern in the access token or ID token.
 */
public class RegexFilterRolesMapper extends AbstractOIDCProtocolMapper
        implements OIDCIDTokenMapper, OIDCAccessTokenMapper {
    public static final String PROVIDER_ID = "regex-roles-mapper";
    static final String REGEX_CONFIG_PROPERTY = "regex.roles";
    static final String INVERT_CONFIG_PROPERTY = "regex.invert";
    private static final Logger LOG = Logger.getLogger(RegexFilterRolesMapper.class);

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        // Regex configuration property
        ProviderConfigProperty whitelistProperty = new ProviderConfigProperty();
        whitelistProperty.setName(REGEX_CONFIG_PROPERTY);
        whitelistProperty.setDefaultValue("");
        whitelistProperty.setLabel("Whitelisted Roles Regular Expression");
        whitelistProperty.setType(STRING_TYPE);
        whitelistProperty.setHelpText("Example: '^ROLE_' includes all roles starting with 'ROLE_'. Use standard Java regex syntax.");
        configProperties.add(whitelistProperty);

        // Invert match configuration property
        ProviderConfigProperty invertMatch = new ProviderConfigProperty();
        invertMatch.setName(INVERT_CONFIG_PROPERTY);
        invertMatch.setLabel("Invert match");
        invertMatch.setType(BOOLEAN_TYPE);
        invertMatch.setHelpText("Include roles that do not match the regex");
        configProperties.add(invertMatch);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, RegexFilterRolesMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
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
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client, ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        if (mapperModel == null || mapperModel.getConfig() == null) {
            return;
        }
        final String regexConfig = mapperModel.getConfig().get(REGEX_CONFIG_PROPERTY);
        if (regexConfig != null && !regexConfig.isEmpty()) {
            try {
                Pattern.compile(regexConfig);
            } catch (PatternSyntaxException ex) {
                throw new ProtocolMapperConfigException("error", "Invalid regex: {0}", ex.getMessage());
            }
        }
        super.validateConfig(session, realm, client, mapperModel);
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        final UserModel user = userSession.getUser();
        if (user == null) {
            return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
        }

        try {
            final String regexConfig = mappingModel.getConfig().get(REGEX_CONFIG_PROPERTY);
            final boolean invertConfig = Boolean.parseBoolean(mappingModel.getConfig().getOrDefault(INVERT_CONFIG_PROPERTY, "false"));
            final String tokenClaimName = mappingModel.getConfig().get(TOKEN_CLAIM_NAME);

            if (regexConfig != null && !regexConfig.isEmpty()) {
                Pattern regex;
                try {
                    regex = Pattern.compile(regexConfig);
                } catch (PatternSyntaxException ex) {
                    LOG.errorf("Invalid regex in mapper '%s': %s", mappingModel.getName(), ex.getMessage());
                    return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
                }

                final Set<String> whitelistedRoles = filterRoles(
                        getDeepUserRoleMappings(user).stream().map(RoleModel::getName),
                        regex,
                        invertConfig
                );
                if (!whitelistedRoles.isEmpty()) {
                    Map<String, Object> claims = token.getOtherClaims();
                    putNestedClaim(claims, tokenClaimName, whitelistedRoles);
                }
                setClaim(token, mappingModel, userSession, session, clientSessionCtx);
            }

        } catch (Exception e) {
            LOG.errorf(e, "Error filtering roles for user '%s' in mapper '%s'", user.getUsername(), mappingModel.getName());
        }
        return super.transformAccessToken(token, mappingModel, session, userSession, clientSessionCtx);
    }

    /**
     * Filters a stream of role names based on a regex pattern.
     * If invert is true, it returns roles that do not match the regex.
     *
     * @param roleNames The stream of role names to filter.
     * @param regex     The regex pattern to match against the role names.
     * @param invert    If true, inverts the match (returns roles that do not match the regex).
     * @return A set of filtered role names.
     */
    static Set<String> filterRoles(Stream<String> roleNames, Pattern regex, boolean invert) {
        return roleNames
                .filter(role -> invert != regex.matcher(role).find())
                .collect(Collectors.toSet());
    }

    /**
     * Puts a value into a nested claim structure in the claims map.
     * If the nested structure does not exist, it will be created.
     *
     * @param claims    The claims map to modify.
     * @param dottedKey The dotted key representing the nested structure (e.g., "nested.claim.key").
     * @param value     The value to set at the specified nested key.
     */
    @SuppressWarnings({"ReassignedVariable", "unchecked"})
    static void putNestedClaim(Map<String, Object> claims, String dottedKey, Object value) {
        final String[] parts = dottedKey.split("\\.");
        Map<String, Object> current = claims;
        for (int i = 0; i < parts.length - 1; i++) {
            String part = parts[i];
            current = (Map<String, Object>) current.computeIfAbsent(part, k -> new HashMap<>());
        }
        current.put(parts[parts.length - 1], value);
    }

}
