# CVE-2019-9880: WPGraphQL 0.2.3 unauthenticated user disclosure

**[CVE-2019-9880](https://www.cve.org/CVERecord?id=CVE-2019-9880) is an
unauthenticated information disclosure** in the WPGraphQL 0.2.3 plugin for
WordPress (CWE-306, CVSS 3.0 9.1). The `users` RootQuery has no authentication
check, so an anonymous GraphQL query returns every WordPress user's id, name,
email address, username and roles.

**Affected:** WPGraphQL 0.2.3 for WordPress.

**Fixed:** WPGraphQL
[0.3.0](https://github.com/wp-graphql/wp-graphql/releases/tag/v0.3.0) or later.

**Severity:** CVSS 3.0 9.1 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`.

## How does the detector verify the disclosure?

It sends one anonymous `POST /graphql` carrying
`query { users { nodes { id name email username roles } } }`. A positive match
requires an HTTP 200 `application/json` response whose body contains the GraphQL
user-listing shape (`{"data":{`, `"name":` and `"roles":`). The same query sent
to a random control path must not return the listing, so a catch-all host is
not reported.

The query only reads data and changes no state; no credential or cookie is sent
and redirects are not followed.

## References

- Pentest Partners advisory — https://www.pentestpartners.com/security-blog/pwning-wordpress-graphql/
- Fixed release 0.3.0 — https://github.com/wp-graphql/wp-graphql/releases/tag/v0.3.0
- NVD — https://nvd.nist.gov/vuln/detail/CVE-2019-9880
- CVE record — https://www.cve.org/CVERecord?id=CVE-2019-9880

## Remediation

Update WPGraphQL to 0.3.0 or later, which restricts the users query to
authenticated requests. Restrict access to the GraphQL endpoint and review the
fields exposed to anonymous clients.
