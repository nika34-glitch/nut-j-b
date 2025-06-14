# Libero Email Validator

## Proxy Feed Fetcher

This repository also includes a separate crate `proxy_feed` for aggregating raw proxy lists.
Use the `fetch` subcommand to download public proxy sources specified in a TOML configuration file and append them to an output list.

```bash
cargo run -p proxy_feed -- fetch --config proxy_feed/example-config.toml --output feeds/all_proxies.txt
```

The example configuration lists several URLs that return HTTP proxy lists.
Any of the sections can be omitted or replaced with your own sources. The optional `proxybroker_cmd` field allows running a custom command that outputs additional proxies.

### OtoProxy helper

For additional proxy sources the repository ships a small Python script
`otoproxy/otoproxy.py`. It scrapes URLs listed in `otoproxy/sites.txt`, tests the
proxies and stores the working ones in the `feeds/` directory. Run it manually
with:

```bash
python otoproxy/otoproxy.py
```

### GUI Front-end

A simple Tkinter interface is available in `gui_frontend.py` for running the validator or any command-line analysis. Launch it with:
```bash
python gui_frontend.py
```
The interface parses the validator output and shows all runtime statistics such as checks per second, remaining count, success rates, and more.

#Tool Description: Libero Email Credential Validator (LECV)
#The Libero Email Credential Validator (LECV) is a controlled-use utility designed for legitimate, consent-based credential verification across large datasets. It is intended strictly for authorized environments such as enterprise IT operations, user-driven credential audits, breach exposure analysis, and sanctioned security research.
#Key legitimate use cases include:
#Enterprise Account Auditing: Organizations that use Libero Mail services internally can use LECV to verify employee credentials during security audits, SSO migration, or policy compliance checks. The tool is to be operated by authorized personnel only and within the bounds of internal security protocols.
#End-User Credential Health Checks: LECV allows users to voluntarily submit or load their own email and password combinations (e.g., exported from password managers) to determine whether their Libero accounts are still accessible. This helps users detect outdated, compromised, or misconfigured credentials. All operations are performed locally and do not store any sensitive data.
#Security Research & Penetration Testing: LECV may be used by certified researchers conducting credential-based testing under responsible disclosure programs or with explicit permission from the account holders or service provider. All usage must adhere to ethical hacking principles and any applicable legal frameworks.
#Breach Exposure Validation: In scenarios where credential dumps or breach datasets are discovered, LECV can be employed—under lawful authority—to validate which Libero credentials are still active. This aids in preparing exposure notifications, deactivating compromised accounts, or reporting incidents to relevant authorities. Use is restricted to environments with clear legal entitlement to act on the data.
#Important Notice:
#LECV must only be used in contexts where explicit consent, organizational ownership, or legal authority exists for all credentials tested. Unauthorized use may violate privacy laws (e.g., GDPR, CFAA, Italian Data Protection Code) and result in criminal liability.
#This tool does not store, share, or transmit any login information. All operations are designed to be performed securely, responsibly, and transparently.
#Libero Email Validator ("the Tool") checks login details for Libero email accounts for ex company employees. It tries POP3 and IMAP servers in quick succession and notes which addresses #work. It can use many network connections at once so big lists finish faster.

## Output Files
The validator writes results to `valid.txt`, `invalid.txt`, and `error.txt` using `email:password` pairs without hashing. Keep these files secure.

