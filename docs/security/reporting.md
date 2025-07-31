# Vulnerability Reporting

Responsible disclosure process for security vulnerabilities in TrojanHorse.js.

## Security Policy

### Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported | End of Life |
|---------|-----------|-------------|
| 2.x.x   | ✅ Yes    | -           |
| 1.9.x   | ✅ Yes    | 2025-12-31  |
| 1.8.x   | ⚠️ Limited | 2025-06-30  |
| < 1.8   | ❌ No     | Already EOL |

### Security Update Policy

- **Critical**: Patches released within 24-48 hours
- **High**: Patches released within 7 days
- **Medium**: Patches released within 30 days
- **Low**: Patches included in next regular release

## Reporting Vulnerabilities

### Preferred Method: Security Email

**Email**: security@trojanhorse-js.com

Please include the following information:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested mitigation (if any)
- Your contact information

### GitHub Security Advisory

For GitHub-hosted repositories, you can also use GitHub's private security advisory feature:

1. Go to the repository's Security tab
2. Click "Report a vulnerability"
3. Fill out the security advisory form

### PGP Encryption (Optional)

For highly sensitive reports, you may encrypt your message using our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[PGP Key would be here in real implementation]
-----END PGP PUBLIC KEY BLOCK-----
```

## What to Report

### In Scope

✅ **Report these types of vulnerabilities:**

- Authentication bypass
- Authorization flaws
- SQL injection
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Remote code execution
- Privilege escalation
- Information disclosure
- Cryptographic vulnerabilities
- API security issues
- Dependency vulnerabilities

### Out of Scope

❌ **Do not report these:**

- Social engineering attacks
- Physical attacks
- DoS attacks (unless amplification > 1000x)
- Issues in third-party services we don't control
- Vulnerabilities in outdated versions (see supported versions)
- Self-XSS that requires user interaction
- CSRF on forms without sensitive actions

## Response Process

### Initial Response (24 hours)

We will acknowledge receipt of your report within 24 hours and provide:
- Confirmation that we received your report
- Initial assessment of the report
- Expected timeline for investigation
- Point of contact for follow-up

### Investigation Timeline

- **1-3 days**: Initial triage and impact assessment
- **1-2 weeks**: Detailed analysis and patch development
- **2-4 weeks**: Testing and validation of the fix
- **Release**: Coordinated disclosure and patch release

### Communication

We will keep you informed throughout the process:
- Regular updates on investigation progress
- Advance notice of patch release timeline
- Credit discussion (if you desire public recognition)

## Disclosure Timeline

### Coordinated Disclosure

We follow responsible disclosure practices:

1. **Day 0**: Vulnerability reported
2. **Day 1**: Acknowledgment sent to reporter
3. **Day 1-7**: Investigation and impact assessment
4. **Day 7-30**: Patch development and testing
5. **Day 30**: Patch release and public disclosure
6. **Day 30+**: Security advisory published

### Extended Timeline

For complex vulnerabilities requiring significant changes:
- We may request up to 90 days for resolution
- Regular progress updates will be provided
- Mutual agreement on disclosure timeline

### Emergency Disclosure

If a vulnerability is being actively exploited:
- Immediate public advisory with mitigations
- Emergency patch within 24-48 hours
- Detailed post-mortem after resolution

## Recognition and Rewards

### Hall of Fame

Security researchers who responsibly disclose vulnerabilities will be recognized in our:
- Security Hall of Fame on our website
- Release notes and security advisories
- Annual security report

### Bug Bounty Program

While we don't currently offer monetary rewards, we do provide:
- Public recognition and attribution
- TrojanHorse.js merchandise
- Early access to new features
- Direct communication channel with the security team

*Note: We are evaluating the implementation of a formal bug bounty program for 2025.*

## Security Advisory Format

When we publish security advisories, they include:

### CVE Information
- CVE identifier (when assigned)
- CVSS score and vector
- CWE classification

### Impact Assessment
- Affected versions
- Attack vectors
- Potential consequences
- Exploitation difficulty

### Technical Details
- Root cause analysis
- Proof of concept (when appropriate)
- Exploitation timeline

### Remediation
- Immediate mitigations
- Patch information
- Upgrade instructions
- Configuration changes

### Credits
- Reporter recognition
- Research team acknowledgments

## Example Security Advisory

```markdown
# Security Advisory: SQL Injection in Threat Query API

**CVE**: CVE-2025-XXXX
**CVSS Score**: 8.8 (High)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Summary
A SQL injection vulnerability was discovered in the threat query API 
endpoint that could allow authenticated users to execute arbitrary 
SQL queries.

## Affected Versions
- TrojanHorse.js 1.8.0 - 1.9.2
- TrojanHorse.js Enterprise 1.8.0 - 1.9.2

## Impact
Authenticated attackers could:
- Access unauthorized threat intelligence data
- Modify or delete existing threat records
- Potentially gain access to API keys and configuration

## Technical Details
The vulnerability exists in the `searchThreats` function where user input
is directly concatenated into SQL queries without proper sanitization.

## Exploitation
Exploitation requires:
- Valid authentication credentials
- Access to the `/api/threats/search` endpoint
- Knowledge of the database schema

## Remediation

### Immediate Mitigation
Disable the search endpoint by setting:
```yaml
api:
  endpoints:
    search: false
```

### Permanent Fix
Upgrade to:
- TrojanHorse.js 1.9.3 or later
- TrojanHorse.js Enterprise 1.9.3 or later

## Timeline
- 2025-01-15: Vulnerability reported by Security Researcher
- 2025-01-15: Initial response and triage
- 2025-01-20: Patch development completed
- 2025-01-25: Patch testing and validation
- 2025-01-29: Public disclosure and patch release

## Credits
Special thanks to [Security Researcher Name] for the responsible 
disclosure of this vulnerability.
```

## Security Best Practices for Users

### Regular Updates
- Enable automatic security updates
- Subscribe to security announcements
- Monitor the security advisories page

### Secure Configuration
- Follow security hardening guides
- Use strong authentication methods
- Enable audit logging
- Regular security assessments

### Monitoring
- Monitor for unusual API activity
- Set up alerting for security events
- Regular log analysis
- Implement threat detection

## Contact Information

### Security Team
- **Email**: security@trojanhorse-js.com
- **Response Time**: 24 hours
- **Languages**: English

### General Inquiries
- **Email**: info@trojanhorse-js.com
- **Documentation**: https://docs.trojanhorse-js.com/security/

### Community
- **GitHub Issues**: For non-security bugs only
- **Discussions**: https://github.com/sc4rfurry/TrojanHorse.js/discussions
- **Twitter**: @trojanhorse_js

---

**Remember**: Please do not publicly disclose security vulnerabilities until we have had a chance to address them. This helps protect all users of TrojanHorse.js.