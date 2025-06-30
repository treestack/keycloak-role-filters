# keycloak-role-filters

A custom Keycloak OIDC protocol mapper that filters user roles by regular expression before adding them to the access token.
This allows you to keep your tokens lean and only expose roles relevant for backend authorization.

---

## Features ✨

- Configurable role filtering using Java-style regular expressions
- Optional invert mode to exclude matching roles instead of including them
- Reduced token size by omitting unnecessary or sensitive roles

## Installation

1. Build the JAR with Maven:
   ```bash
   mvn clean package
   ```
2. Copy the resulting JAR (e.g., `target/keycloak-regex-roles-mapper-1.0.0.jar`) into the Keycloak providers directory:
   - For standalone Keycloak:
     ```bash
     cp target/keycloak-regex-roles-mapper-*.jar /opt/keycloak/providers/
     ```
   - Or the equivalent directory in your Keycloak installation.
3. Restart Keycloak:
   ```bash
   /opt/keycloak/bin/kc.sh restart
   ```

## Usage

1. Log into the Keycloak Admin Console.
2. Navigate to your **client** (or client scope) → **Mappers** → **Create mapper**.
3. Choose:
   - Mapper Type: **Whitelist by Regex Roles Mapper**
4. Configure:
   - **Whitelisted Roles Regular Expression**: A regex pattern that matches any part of a role name to include it in the token. For example, `ROLE_` matches any role containing `ROLE_`, such as `PAROLE_OFFICER`. If you only want roles that *start with* `ROLE_`, use `^ROLE_`. Matching is case-sensitive.
   - **Invert match**: If enabled, roles **not** matching the regex will be included instead (i.e., regex acts as a blacklist).
   - **Token Claim Name**: The claim name under which the filtered roles appear in the token (e.g., `realm_access.roles` or a custom claim like `user_roles`). Supports nested claims via dot notation (e.g., `foo.bar`).
5. Save the mapper.

Only roles matching your regex (or excluded by invert) will appear in tokens issued for this client.

## Why use this?

In many systems, users have multiple roles — some controlling permissions in the backend (critical), others enabling UI features (optional). By filtering which roles are exposed in tokens, you:
- Improve performance (smaller tokens, faster processing)
- Reduce attack surface (sensitive roles stay hidden)
- Keep feature toggles separate from security-critical roles

## Contributing

PRs and issues are welcome!
Please open an issue if you encounter problems or have suggestions for improvements.

## License

This project is licensed under the MIT License.
