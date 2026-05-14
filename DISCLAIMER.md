# Disclaimer and Safety Notice

This project is provided for educational and operational use at your own risk.

By using, modifying, or distributing this software, you acknowledge and agree:

- No warranty is provided (express or implied).
- The author is not liable for data loss, downtime, security incidents, or any direct/indirect damages.
- You are responsible for secure deployment, key/certificate management, backups, and legal compliance.
- You should test thoroughly in a non-production environment before production use.

This notice is supplemental to the terms in the MIT license.

## Recommended Operator Safety Practices

- Keep `API_KEY` secret and rotate it regularly.
- Use TLS in production (`USE_TLS=true`) with valid certificates.
- Restrict server port exposure using firewall rules or network ACLs.
- Run the service with least-privilege OS permissions.
- Maintain frequent backups of synchronized files.
