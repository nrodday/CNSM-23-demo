%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

%define package_num  0
%define major_ver    2
%define minor_ver    1
%define update_num   11
%define lib_ver_info 2.0.1

%define lib_version_info %{lib_ver_info}
%define package_version %{package_num}.%{major_ver}.%{minor_ver}.%{update_num}
%define version %{package_version}
%define name bgpsecio

Name:%{name}
Version:%{version}
Release:	1%{?dist}
Summary: A BGP4/BGPsec traffic generator with many features

Group:Networking/Tools
License:https://www.nist.gov/director/copyright-fair-use-and-licensing-statements-srd-data-and-software
URL:https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype
Source0:%{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Prefix: %{_prefix}

BuildRequires:automake
Requires(pre): srxcryptoapi >= 0.3.0 srxcryptoapi < 0.4.0
Requires:glibc libconfig >= 1.3 openssl >= 1.0.1e readline >= 6.0 srxcryptoapi >= 0.3.0 srxcryptoapi < 0.4.0

%description
BGPsec-IO is a BGPsec traffic generator that allows to generate multi hop fully
signed BGPsec UPDATE messages and send them to a BGPsec capable router. In
addition, it allows to only generate a multi hop fully signed BGPsec_PATH 
attribute to test plugins developed for the SRxCryptoAPI.

%prep
%setup -q

%build
%configure --prefix=/usr --sysconfdir=/etc
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%post
ldconfig

%postun
ldconfig

%files
%defattr(-,root,root,-)
%doc
%{_bindir}/bgpsecio
%{_bindir}/bio-traffic.sh
%{_bindir}/mrt_to_bio.sh
%{_libdir}/libantd_util.so.%{lib_version_info}
%{_libdir}/libantd_util.so.%{major_ver}
%{_libdir}/libantd_util.so
%exclude %{_libdir}/libantd_util.a
%exclude %{_libdir}/libantd_util.la
