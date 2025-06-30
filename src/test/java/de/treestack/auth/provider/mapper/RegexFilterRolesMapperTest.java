package de.treestack.auth.provider.mapper;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.ProtocolMapperConfigException;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class RegexFilterRolesMapperTest {

    @Test
    void filterRoles() {
        Pattern pattern = Pattern.compile("^ROLE_");
        Stream<String> roles = Stream.of("ROLE_ADMIN", "PAROLE_OFFICER", "USER");
        Set<String> result = RegexFilterRolesMapper.filterRoles(roles, pattern, false);
        assertEquals(Set.of("ROLE_ADMIN"), result);
    }

    @Test
    void testFilterRolesNoRoles() {
        Pattern pattern = Pattern.compile(".*");
        Stream<String> roles = Stream.of();
        Set<String> result = RegexFilterRolesMapper.filterRoles(roles, pattern, false);
        assertTrue(result.isEmpty(), "Expected empty result for no input roles");
    }

    @Test
    void testFilterRolesInverted() {
        Pattern pattern = Pattern.compile("^ROLE_");
        Stream<String> roles = Stream.of("ROLE_ADMIN", "USER");
        Set<String> result = RegexFilterRolesMapper.filterRoles(roles, pattern, true);
        assertEquals(Set.of("USER"), result);
    }

    @Test
    void testFilterRolesNoMatches() {
        Pattern pattern = Pattern.compile("^ADMIN_");
        Stream<String> roles = Stream.of("ROLE_USER", "ROLE_VIEWER");
        Set<String> result = RegexFilterRolesMapper.filterRoles(roles, pattern, false);
        assertTrue(result.isEmpty(), "Expected empty result if no roles match the regex");
    }

    @Test
    void testFilterRolesNoMatchesInverted() {
        Pattern pattern = Pattern.compile("^ADMIN_");
        Stream<String> roles = Stream.of("ROLE_USER", "ROLE_VIEWER");
        Set<String> result = RegexFilterRolesMapper.filterRoles(roles, pattern, true);
        assertEquals(Set.of("ROLE_USER", "ROLE_VIEWER"), result, "Expected all roles if invert=true and no roles match");
    }

    @Test
    void testValidateConfigWithInvalidRegexThrows() {
        ProtocolMapperModel mapperModel = new ProtocolMapperModel();
        mapperModel.setConfig(Map.of(RegexFilterRolesMapper.REGEX_CONFIG_PROPERTY, "[invalid"));

        RegexFilterRolesMapper mapper = new RegexFilterRolesMapper();
        assertThrows(
                ProtocolMapperConfigException.class,
                () -> mapper.validateConfig(null, null, null, mapperModel)
        );
    }


    @Test
    void testPutNestedClaimCreatesNestedStructure() {
        Map<String, Object> claims = new HashMap<>();
        RegexFilterRolesMapper.putNestedClaim(claims, "foo.bar.baz", "value");

        assertTrue(claims.containsKey("foo"), "Top-level key 'foo' should exist");
        Object barObj = claims.get("foo");
        assertTrue(barObj instanceof Map, "'foo' should map to a Map");

        Map<?, ?> barMap = (Map<?, ?>) barObj;
        assertTrue(barMap.containsKey("bar"), "Second-level key 'bar' should exist");
        Object bazObj = barMap.get("bar");
        assertTrue(bazObj instanceof Map, "'bar' should map to a Map");

        Map<?, ?> bazMap = (Map<?, ?>) bazObj;
        assertEquals("value", bazMap.get("baz"), "The final key 'baz' should map to the expected value");
    }

    @Test
    void testPutNestedClaimOverwritesExistingValue() {
        Map<String, Object> claims = new HashMap<>();
        RegexFilterRolesMapper.putNestedClaim(claims, "foo.bar", "first");
        RegexFilterRolesMapper.putNestedClaim(claims, "foo.bar", "second");

        Object fooObj = claims.get("foo");
        assertTrue(fooObj instanceof Map);
        Map<?, ?> fooMap = (Map<?, ?>) fooObj;
        assertEquals("second", fooMap.get("bar"), "Existing value should be overwritten with the latest call");
    }

    @Test
    void testPutNestedClaimSingleLevel() {
        Map<String, Object> claims = new HashMap<>();
        RegexFilterRolesMapper.putNestedClaim(claims, "simple", 42);

        assertEquals(42, claims.get("simple"), "Single-level key should map directly");
    }

}