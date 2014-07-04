
Summary   : Oracle Password Repository.
Summary(ru_RU.UTF-8): Репозиторий паролей для СУБД Oracle.
Name      : opr
Version   : 1.1
Release   : 12.1
Group     : utils

Packager  : Kryazhevskikh Sergey, <soliverr@gmail.com>
License   : GPL v2
URL       : http://sourceforge.net/projects/opr

Requires  : oracle-client
BuildArch : x86_64, x86

Source    : %{name}-%{version}.tar.gz
BuildRoot : %{_tmppath}/%{name}-%{version}
BuildRequires: oracle-client

%define package_doc_dir %{_datadir}/doc/%{name}-%{version}
%define pkg_build_dir   %{_builddir}/%{name}-%{version}
%define opr_repos_dir   /etc/oracle
%define opr_repos_file  repos.opr

%description
The OPR is a UNIX command line tool that allows you to remove hardcoded Oracle
passwords from your UNIX scripts. For example, consider the following script:
.
  #!/bin/sh
  sqlplus -s /NOLOG << EOF
  connect system/manager@testdb
  exec dbms_utility.analyze_database('COMPUTE');
  EOF
.

%description -l ru_RU.UTF-8
OPR - утилита, поддерживающая репозитарий паролей для СУБД Oracle, а
также синхронное изменение паролей в репозитарии и базе данных. Утилита
позволяет отказаться от использования "зашитых" в программы паролей к
схемам данных БД, например:
.
  #!/bin/sh
  sqlplus -s /NOLOG << EOF
  connect system/manager@testdb
  exec dbms_utility.analyze_database('COMPUTE');
  EOF
.

%prep

%setup -q
./build.sh
./configure --prefix=%{_prefix} \
            --localstatedir=%{_localstatedir} \
            --sysconfdir=%{_sysconfdir} \
            --mandir=%{_mandir} \
            --with-docdir=%{_datadir}/doc/%{name}-%{version} \
            --with-system-libtool \
            --disable-ltdl-install \
            --with-ltdl-include=/usr/include \
            --with-oprreposdir=%{opr_repos_dir}

%build
%{__make}

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%{__make} install DESTDIR=$RPM_BUILD_ROOT/

# Install documentation
%{__install} -D --mode 0644 TODO $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 README $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 NEWS $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 AUTHORS $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 INSTALL $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 COPYING $RPM_BUILD_ROOT%{package_doc_dir}
%{__install} -D --mode 0644 ChangeLog $RPM_BUILD_ROOT%{package_doc_dir}

# Install directory for password repository
%{__install} --directory --mode 0755 $RPM_BUILD_ROOT%{opr_repos_dir}


%pre

%preun

%post
# Create password repository
su oracle -c "/usr/sbin/opr -c" || true

%postun

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
[ "%{pkg_build_dir}" != "/" ] && rm -rf %{pkg_build_dir}

%files
%defattr(-,root,root)
%dir %{_sbindir}
%doc %{package_doc_dir}
#%config %attr(600,oracle,dba) %{opr_repos_dir}/%{opr_repos_file}
%attr (4510,oracle,rias) %{_sbindir}/opr
%attr(0644, root, root) %{_mandir}/man8/*

%changelog
* Tue May 04 2010 Kryazhevskikh Sergey <soliverr@gmail.com> - 1.1-11.5 18:33:33 +0600
 - Fixed package dependencies;
 - Added simple man-page.

* Wed Apr 08 2009 Kryazhevskikh Sergey <soliverr@gmail.com> - 1.1-11.4
 - Ignore install error if password repository file already exists.

* Wed Feb 25 2009 Kryazhevskikh Sergey <soliverr@gmail.com> - 1.1-11.3
 - Create password repository on package install;
 - Fixed error with libpath.

* Thu Feb 24 2009 Kryazhevskikh Sergey <soliverr@gmail.com> - 1.1-11.2
 - Get ORACLE_HOME environment variable before read oratab file.
 
* Wed Feb  4 2009 Kryazhevskikh Sergey <soliverr@gmail.com> - 1.1-11.1
 - Initial package build from sources 1.1-11;
 - Added default location for password repository.
