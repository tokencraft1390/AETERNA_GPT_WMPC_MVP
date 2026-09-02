# Security Policy

## Supported status

AETERNA GPT WMPC MVP is under active development and is not production-approved unless a release record explicitly says so.

## Reporting

Do not publish vulnerabilities, credentials, personal data, or exploit details in a public issue. Report them to the repository owner through a previously verified private channel. Include the affected commit, reproduction steps, impact, and proposed mitigation. Do not perform destructive testing or access other users' data.

## Controls

- Never commit secrets, private keys, seed phrases, tokens, passwords, webhook secrets, customer data, or production configuration.
- Separate development and production credentials and use least privilege.
- External sending, publishing, deployment, spending, data export, credential changes, and wallet actions require explicit owner approval.
- Security checks, rollback instructions, and recovery evidence are required before release.
- Suspected credentials must be revoked and rotated; removing them from the newest commit is not sufficient.
- Third-party code, media, fonts, models, and data require documented licenses and provenance.
- Cryptographic, identity, model, and privacy claims require tests and independent review before production use.
