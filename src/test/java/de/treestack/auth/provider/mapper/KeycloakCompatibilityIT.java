package de.treestack.auth.provider.mapper;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import static org.junit.jupiter.api.Assertions.assertTrue;

class KeycloakCompatibilityIT {

    @ParameterizedTest
    @ValueSource(strings = {
            "22.0.5",
            "23.0.7",
            "24.0.5",
            "25.0.6",
            "26.2.5"
    })
    void testKeycloakStartsWithMapper(String keycloakVersion) {
        String image = "quay.io/keycloak/keycloak:" + keycloakVersion;
        try (KeycloakContainer keycloak = new KeycloakContainer(image)
                .waitingFor(Wait.forLogMessage(".*Keycloak.*started.*", 1))
                .withCopyFileToContainer(
                        MountableFile.forHostPath("target/regex-filter-protocol-mapper-1.1-SNAPSHOT-keycloak-22+.jar"),
                        "/opt/keycloak/providers/regex-filter-protocol-mapper.jar")
        )
        {
            keycloak.start();

            String logs = keycloak.getLogs();
            assertTrue(logs.contains("de.treestack.auth.provider.mapper.RegexFilterRolesMapper"),
                    "Expected custom mapper to be loaded in Keycloak " + keycloakVersion);
        }
    }
}
