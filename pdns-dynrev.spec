Summary: PowerDNS Dynamic Reverse Backend
Name: pdns-dynrev
Version: 1.0
Release: 0
License: MIT
Group: System Environment/Daemons
Source: https://github.com/bevhost/PowerDNS-Dynamic-Reverse-Backend/archive/master.zip
Packager: David Beveridge <dave@bevhost.com>
Requires: python3-netaddr python3-py-radix python3-pyyaml
BuildArch: noarch

%description
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

%prep
%autosetup -n PowerDNS-Dynamic-Reverse-Backend-master

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_sysconfdir}/pdns
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
install -m 0755 pdns-dynamic-reverse-backend.py %{buildroot}%{_sbindir}/pdns-dynamic-reverse-backend.py
install -m 0644 dynrev.yml %{buildroot}%{_sysconfdir}/pdns/dynrev.yml
install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README

%clean
rm -rf %{buildroot}

%pre 

%post

%files
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/pdns/dynrev.yml
%attr(0755,root,root) %{_sbindir}/pdns-dynamic-reverse-backend.py
%attr(0644,root,root) %{_docdir}/%{name}/README

%changelog
* Thu Jun 04 2026 David Beveridge <dave@bevhost.com>
- Remove pathfix.py, hardcode to python 3, so python 2.7 no longer supported
- Replace IPy module with Python 3 native ipaddress module (vibe code)
- Create get_reverse_pointer() and get_reverse_names() helper functions
- Update parse_config() to use ipaddress.ip_network()
- Remove IPy from requirements.txt and Requires: since ipaddress is built-in

* Thu Jun 27 2024 David Beveridge <dave@bevhost.com>
- Use pathfix.py to set the shebang to python version

* Sat Nov 09 2019 David Beveridge <dave@bevhost.com>
- initial build

