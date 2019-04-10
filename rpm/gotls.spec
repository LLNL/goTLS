Name:           gotls
Version:        0.1.0
Release:        1%{?dist}
Summary:        gotls is an automated TLS certificate issuance and management tool

License:        MIT
URL:            https://mybitbucket.llnl.gov/projects/COMPWEBDEV/repos/gotls
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang

%description
gotls is an automated TLS certificate issuance and management tool. It can
generate keys, CSRs, and optionally obtain the certificate with an internal
Active Directory Certificate Services endpoint.

# https://github.com/rpm-software-management/rpm/issues/367
%global _missing_build_ids_terminate_build 0
%define debug_package %{nil}

%prep
%autosetup

%build
make %{?_smp_mflags}

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_mandir}/man8
install -p -m 755 gotls %{buildroot}%{_bindir}/gotls
install -p -m 644 rpm/man/gotls.8 %{buildroot}%{_mandir}/man8/gotls.8
install -p -m 644 rpm/man/gotls-cert.8 %{buildroot}%{_mandir}/man8/gotls-cert.8
install -p -m 644 rpm/man/gotls-cert-adcs.8 %{buildroot}%{_mandir}/man8/gotls-cert-adcs.8
install -p -m 644 rpm/man/gotls-csr.8 %{buildroot}%{_mandir}/man8/gotls-csr.8
install -p -m 644 rpm/man/gotls-key.8 %{buildroot}%{_mandir}/man8/gotls-key.8

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%{_bindir}/gotls
%{_mandir}/man8/gotls.8*
%{_mandir}/man8/gotls-cert.8*
%{_mandir}/man8/gotls-cert-adcs.8*
%{_mandir}/man8/gotls-csr.8*
%{_mandir}/man8/gotls-key.8*

#%doc README
%license LICENSE

%changelog
* Wed Apr 10 2019 Ian Freeman <ifreeman@llnl.gov>
- Initial release with ADCS endpoint issuance support
