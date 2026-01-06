# Regex Filter Protocol Mapper

A custom Keycloak OIDC protocol mapper that filters user roles by regular expression before adding them to the access token.
This allows you to keep your tokens lean and only expose roles relevant for backend authorization.

---

## Filtering Keycloak Roles with Regex

Have you ever connected Keycloak to an LDAP or a corporate SSO system, only to find your users showered with hundreds 
of roles - many of which you don’t even recognize? We did.

So we built a custom Keycloak protocol mapper: the `RegexFilterRolesMapper`. It filters roles before they hit the 
access token or ID token, keeping only those that match a configurable regular expression. For example, you might want 
to include only roles starting with `APP_`, ignoring the deluge of `AD_Group_*` or irrelevant legacy permissions.

### How It Works

This mapper iterates over the user’s effective roles, filters them using a configurable regex (with optional inversion 
for those who prefer the world upside down), and writes the result as a claim into the token. You can use nested 
claim keys like `realm_access.filtered_roles` to maintain compatibility with Keycloak's standards.

## Security implications

> [!WARNING]  
> Shouldn’t the groups be clean in the source directory instead of hacking around in Keycloak?
> Yes, they should. Ideally, your LDAP or IdP should only send relevant groups. But in the real world - especially in
> large enterprises - that’s often a pipe dream. Sometimes, cleaning up legacy directories is simply
> not possible or a diplomatic nightmare.
>
> So, yes, this mapper is a band-aid. But it’s a practical, lightweight band-aid that solves a problem many of us face 
> right now.

## Features ✨

- Configurable role filtering using Java-style regular expressions
- Optional invert mode to exclude matching roles instead of including them
- Reduced token size by omitting unnecessary or sensitive roles

## Prerequisites

This mapper requires Keycloak 22.0.0 or later. It's tested with all major Keycloak versions up to 26.2 and should work 
with any version that supports custom protocol mappers. To be completely sure, compile it against your specific 
Keycloak version (see below).

## Installation

Just copy the JAR into your Keycloak `providers` directory and restart Keycloak. No complex setup required!

## Compilation

Keycloak wants Java 17, so make sure you have that installed. The project uses Maven for building.

1. Build the JAR:
   ```bash
   mvn clean package
   ```
2. Copy the resulting JAR (e.g., `target/regex-filter-protocol-mapper-1.1-SNAPSHOT-keycloak-22+.jar`) into Keycloak's 
providers directory:
   - For standalone Keycloak:
     ```bash
     cp target/regex-filter-protocol-mapper-*.jar /opt/keycloak/providers/
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

Only roles matching your regex (or excluded by the invert option) will appear in tokens issued for this client:

```json
{
  "realm_access": {
    "roles": [
      "ROLE_ADMIN",
      "ROLE_USER"
    ]
  }
}
```



## Contributing

PRs and issues are welcome!
Please open an issue if you encounter problems or have suggestions for improvements.

## License

This project is licensed under the MIT License.
