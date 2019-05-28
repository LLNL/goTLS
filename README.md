goTLS
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

Compiled binaries can be found at the [releases page](https://github.com/llnl/gotls/releases).

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


Contributing
------------

Contributions to goTLS are most welcome. Please note any bugs or suggestions
you have to the [issue tracker](https://github.com/llnl/gotls/issues). [Pull
requests](https://help.github.com/articles/using-pull-requests) can be
targeted directly to the master branch. As noted below, all contributions must
be made under the MIT license.


License
-------

goTLS is distributed under the terms of the MIT license. All new contributions
must be made under this license.

See [LICENSE](https://github.com/llnl/gotls/blob/develop/LICENSE) and
[NOTICE](https://github.com/llnl/gotls/blob/develop/NOTICE) for details.

SPDX-License-Identifier: MIT

LLNL-CODE-775069

