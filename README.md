GoTLS
-----

goTLS is an automated TLS certificate issuance and management tool for Windows,
Mac, and Linux. It can generate keys, CSRs, and optionally obtain the
certificate with an internal Active Directory Certificate Services (ADCS)
endpoint.

Eventually the tool should be able to:
- Obtain certificates via the ADCS SCEP API (if available on your ADCS
installation)
- Obtain certificates via ACME protocol from Let's Encrypt
- Monitor, report, and act on expring certificates on the system


Install
-------

Download links from the source control repository are still pending.

Although values can be supplied at invocation via options, it is suggested to
populate a config file in the home directory with default values. If the ADCS
endpoint will be used to obtain certificates, the endpoint URL and template
name values are also required to be set.

Create a .gotls.yaml file in the user's home directory and change the default
values for your needs:
```
C: US
ST: California
L: Any Town
O: Example Company
OU:
EMAIL: webmaster@example-site.com
ADCS-URL: https://adcs-server.example-company.com/certsrv
OID-TEMPLATE: WebServerv1.0Template
```

The OID-TEMPLATE value can be found by visiting the /certsrv/certrqad.asp page of the
ADCS installation endpoint and examining the value of the Certificate Template
dropdown. Example:
```
<select name="lbCertTemplate" id="lbCertTemplateID">
  <option value="O;WebServerv1.0Template;1;134.[snip] Web Server v1.0 Template">Web Server v1.0 Template</option>
</select>
```
In this case, `WebServerv1.0Template` is the value to set for OID-TEMPLATE.


Usage
-----

Using the tool is done in two stages:

    1. Generate the CSR
    2. Obtain the certificate from the issuer

1. Generate the CSR
-------------------
$ gotls csr hostname.llnl.gov optional-other-hostnames.llnl.gov

hostname.llnl.gov.csr will be created in the current dir. It will also generate a key if not previously present: hostname.llnl.gov.key


2. Obtain the certificate from the issuer
-----------------------------------
If you have signing authority for an ADCS endpoint, you can obtain the cert:

$ gotls cert adcs hostname.llnl.gov.csr

