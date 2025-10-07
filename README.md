goTLS
=====
goTLS is an automated TLS certificate issuance and management tool for Windows,
Mac, and Linux. It can generate keys, CSRs, and optionally obtain the
certificate with an internal Active Directory Certificate Services (ADCS)
endpoint.


Install
-------
Compiled binaries can be found at the [releases page](https://github.com/llnl/gotls/releases).


Configure
---------
Although values can be supplied at invocation time via options, it may be beneficial to
populate a config file with most values. Create a .gotls.yaml file in either the user's home
directory (or the current directory) with as many of the following values set as desired:
```
C: US
ST: California
L: Any Town
O: Example Company
OU:
email: webmaster@example-company.com
adcs-url: https://adcs-server.example-company.com/certsrv
oid-template: WebServerv1.0Template
adcs-auth:
  method: kerberos
  krb5conf: /etc/krb5.conf
  user: myusername
  realm: EXAMPLE-COMPANY.COM
  keytab: /home/myusername/.ssh/keytabs/.keytab
  kdcs:
  - kdc1.example-company.com
  - kdc2.example-company.com
```

To obtain a certificate from an ADCS endpoint, the adcs-url and oid-template
values must be set either in config or via options.

The adcs-auth method can be either ntlm or kerberos. For kerberos authentication,
set the realm. If krb5conf is not set, kdcs will be used to generate a default
krb5 config file. If keytab is not set, a password prompt will be presented.

The oid-template value can be found by visiting the /certsrv/certrqad.asp page of the
ADCS installation endpoint and examining the value of the Certificate Template
dropdown. Example:
```
<select name="lbCertTemplate" id="lbCertTemplateID">
  <option value="O;WebServerv1.0Template;1;134.[snip] Web Server v1.0 Template">Web Server v1.0 Template</option>
</select>
```

In this case, `WebServerv1.0Template` is the value to set for oid-template.


Usage
-----
Using the tool is done in two stages:
### Generate the CSR
    $ gotls csr hostname.example-company.com optional-other-hostname.example-company.com

hostname.example-company.com.csr will be created in the current dir. It will also generate
hostname.example-company.com.key if not previously present.

All provided hostname and ip arguments will be added to the SAN field. The first provided argument will also be set in
the CN field.

You can optionally specify hostnames with the `dns:` prefix, or IP addresses with the `ip:` prefix, but gotls will
parse them properly without the prefixes:

    $ gotls csr dns:hostname.example-company.com optional-other-hostname.example-company.com ip:10.17.50.30


### Obtain the certificate from the issuer
If you have signing authority for an ADCS endpoint, you can obtain the cert:

    $ gotls cert adcs hostname.example-company.com.csr


Contributing
------------
Contributions to goTLS are most welcome. Please note any bugs or suggestions
you have to the [issue tracker](https://github.com/llnl/gotls/issues). [Pull
requests](https://help.github.com/articles/using-pull-requests) can be
targeted directly to the master branch. As noted below, all contributions must
be made under the MIT license.


Building
--------
To build the goTLS binary from source, install go >= 1.23.0 and then run make in the working copy. It will
create a gotls binary in the bin sub-directory.

### Build gotls binary
To compile for a different OS (assuming GOARCH on the build system is the same as on the target OS):
    $ GOOS=darwin make
    $ GOOS=windows make

When compiling for windows on linux, you must first install the MINGW toolchain for your OS:
    # dnf install mingw64-gcc mingw64-gcc-c++
    # apt install gcc-mingw-w64 gcc-multilib

If building on linux for Windows and the path to MINGW system root is not `/usr/x86_64-w64-mingw32/sys-root`
as is the case on Debian/Fedora/RedHat, you must override the `BUILD_VAR` variable (in this case for Arch Linux):
    $ BUILD_VAR='CGO_ENABLED=1 CC="x86_64-w64-mingw32-gcc --sysroot=/usr/x86_64-w64-mingw32"'

Override GOARCH if needed:
    $ GOOS=windows GOARCH=arm64 make

If building on linux for Windows for other than GOARCH=amd64, override CC in the `BUILD_VAR` variable (in this case GOARCH=arm64):
    $ BUILD_VAR='CGO_ENABLED=1 CC="aarch64-linux-gnu-gcc --sysroot=/usr/x86_64-w64-mingw32/sys-root"'

To see all GOOS and GOARCH possible combinations:
    $ go tool dist list

### Build package/installer
To create a Windows installer in the bin sub-directory:
    $ GOOS=windows make wininstaller

To create rpm package, see [rpm/README.md](https://github.com/LLNL/goTLS/blob/master/rpm/README.md).

Future work
-----------
Eventually the tool should be able to:
- [x] Support kerberos authentication
- [x] Support IP addresses in the CSR SAN field
- [ ] Obtain certificates via the ADCS SCEP API (if available on your ADCS
  installation)
- [ ] Obtain certificates via ACME protocol from Let's Encrypt
- [ ] Monitor, report, and act on expiring certificates on the system


License
-------
goTLS is distributed under the terms of the MIT license. All new contributions
must be made under this license.

See [LICENSE](https://github.com/llnl/gotls/blob/master/LICENSE) and
[NOTICE](https://github.com/llnl/gotls/blob/master/NOTICE) for details.

SPDX-License-Identifier: MIT

LLNL-CODE-775069

