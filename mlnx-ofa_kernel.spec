#
# Copyright (c) 2012 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
#

# KMP is disabled by default
%{!?KMP: %global KMP 0}

%global WITH_SYSTEMD %(if ( test -d "%{_unitdir}" > /dev/null); then echo -n '1'; else echo -n '0'; fi)

%{!?configure_options: %global configure_options --with-core-mod --with-user_mad-mod --with-user_access-mod --with-addr_trans-mod --with-mlx5-mod --with-mlxfw-mod --with-ipoib-mod}

%global MEMTRACK %(if ( echo %{configure_options} | grep "with-memtrack" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global MADEYE %(if ( echo %{configure_options} | grep "with-madeye-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%global WINDRIVER %(if (grep -qiE "Wind River" /etc/issue /etc/*release* 2>/dev/null); then echo -n '1'; else echo -n '0'; fi)
%global POWERKVM %(if (grep -qiE "powerkvm" /etc/issue /etc/*release* 2>/dev/null); then echo -n '1'; else echo -n '0'; fi)
%global BLUENIX %(if (grep -qiE "Bluenix" /etc/issue /etc/*release* 2>/dev/null); then echo -n '1'; else echo -n '0'; fi)
%global XENSERVER65 %(if (grep -qiE "XenServer.*6\.5" /etc/issue /etc/*release* 2>/dev/null); then echo -n '1'; else echo -n '0'; fi)

%global IS_RHEL_VENDOR "%{_vendor}" == "redhat" || ("%{_vendor}" == "bclinux") || ("%{_vendor}" == "openEuler")
%global KMOD_PREAMBLE "%{_vendor}" != "openEuler"

# MarinerOS 1.0 sets -fPIE in the hardening cflags
# (in the gcc specs file).
# This seems to break only this package and not other kernel packages.
%if "%{_vendor}" == "mariner" || "%{_vendor}" == "azl" || (0%{?rhel} >= 10)
%global _hardened_cflags %{nil}
%endif

# WA: Centos Stream 10 kernel doesn't support PIC mode, so we removed the following flags
%if (0%{?rhel} >= 10)
%global _hardening_gcc_ldflags %{nil}
%global _gcc_lto_cflags %{nil}
%endif


%if (0%{?fedora} >= 39)
%global _hardening_gcc_cflags %{nil}
%global _gcc_lto_cflags %{nil}
# A way to override -fexceptions:
%global _legacy_options -fcommon -fno-exceptions
%endif


%{!?KVERSION: %global KVERSION %(uname -r)}
%global kernel_version %{KVERSION}
%global krelver %(echo -n %{KVERSION} | sed -e 's/-/_/g')
# take path to kernel sources if provided, otherwise look in default location (for non KMP rpms).
%{!?K_SRC: %global K_SRC /lib/modules/%{KVERSION}/build}

# Select packages to build

# Kernel module packages to be included into kernel-ib
%global build_ipoib %(if ( echo %{configure_options} | grep "with-ipoib-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_oiscsi %(if ( echo %{configure_options} | grep "with-iscsi-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)
%global build_mlx5 %(if ( echo %{configure_options} | grep "with-mlx5-mod" > /dev/null ); then echo -n '1'; else echo -n '0'; fi)

%{!?LIB_MOD_DIR: %global LIB_MOD_DIR /lib/modules/%{KVERSION}/updates}

%{!?IB_CONF_DIR: %global IB_CONF_DIR /etc/infiniband}

%{!?KERNEL_SOURCES: %global KERNEL_SOURCES /lib/modules/%{KVERSION}/source}

%{!?_name: %global _name mlnx-ofa_kernel}
%{!?_version: %global _version 25.04}
%{!?_release: %global _release OFED.25.04.0.6.0.1}
%global _kmp_rel %{_release}%{?_kmp_build_num}%{?_dist}

%global utils_pname %{_name}
%global devel_pname %{_name}-devel
%global non_kmp_pname %{_name}-modules

Summary: Infiniband HCA Driver
Name: %{_name}
Version: %{_version}
Release: %{_release}%{?_dist}
License: GPLv2
Url: http://www.mellanox.com/
Group: System Environment/Base
Source: %{_name}-%{_version}.tgz
BuildRoot: %{?build_root:%{build_root}}%{!?build_root:/var/tmp/OFED}
Vendor: Mellanox Technologies
Obsoletes: kernel-ib
Obsoletes: mlnx-en
Obsoletes: mlnx_en
Obsoletes: mlnx-en-utils
Obsoletes: kmod-mlnx-en
Obsoletes: mlnx-en-kmp-default
Obsoletes: mlnx-en-kmp-xen
Obsoletes: mlnx-en-kmp-trace
Obsoletes: mlnx-en-doc
Obsoletes: mlnx-en-debuginfo
Obsoletes: mlnx-en-sources
Obsoletes: kmod-mellanox
Requires: mlnx-tools >= 5.2.0
Requires: coreutils
Requires: pciutils
Requires: grep
Requires: procps
Requires: module-init-tools
Requires: lsof
%if "%{KMP}" == "1"
BuildRequires: %kernel_module_package_buildreqs
BuildRequires: /usr/bin/perl
%endif
%if "%{_vendor}" == "suse"
%if 0%{?sle_version} >= 150600
Requires: systemd-sysvcompat
%endif
%endif
%description
InfiniBand "verbs", Access Layer  and ULPs.
Utilities rpm.
The driver sources are located at: http://www.mellanox.com/downloads/ofed/mlnx-ofa_kernel-25.04-0.6.0.tgz


# build KMP rpms?
%if "%{KMP}" == "1"
%global kernel_release() $(make -s -C %{1} kernelrelease M=$PWD)
# prep file list for kmp rpm
%(cat > %{_builddir}/kmp.files << EOF
%defattr(644,root,root,755)
/lib/modules/%2-%1
%if %{IS_RHEL_VENDOR}
%config(noreplace) %{_sysconfdir}/depmod.d/zz01-%{_name}-*.conf
%endif
EOF)
%(echo "Obsoletes: kmod-mlnx-rdma-rxe, mlnx-rdma-rxe-kmp, kmod-mellanox, kmod-mellanox-ethernet, kmod-mellanox-nvme" >> %{_builddir}/preamble)
%if %KMOD_PREAMBLE
%kernel_module_package -f %{_builddir}/kmp.files -r %{_kmp_rel} -p %{_builddir}/preamble
%else
%kernel_module_package -f %{_builddir}/kmp.files -r %{_kmp_rel}
%endif
%else # not KMP
%global kernel_source() %{K_SRC}
%global kernel_release() %{KVERSION}
%global flavors_to_build default
%package -n %{non_kmp_pname}
Obsoletes: kernel-ib
Obsoletes: mlnx-en
Obsoletes: mlnx_en
Obsoletes: mlnx-en-utils
Obsoletes: kmod-mlnx-en
Obsoletes: mlnx-en-kmp-default
Obsoletes: mlnx-en-kmp-xen
Obsoletes: mlnx-en-kmp-trace
Obsoletes: mlnx-en-doc
Obsoletes: mlnx-en-debuginfo
Obsoletes: mlnx-en-sources
Obsoletes: mlnx-rdma-rxe
Version: %{_version}
Release: %{_release}.kver.%{krelver}
Summary: Infiniband Driver and ULPs kernel modules
Group: System Environment/Libraries
%description -n %{non_kmp_pname}
Core, HW and ULPs kernel modules
Non-KMP format kernel modules rpm.
The driver sources are located at: http://www.mellanox.com/downloads/ofed/mlnx-ofa_kernel-25.04-0.6.0.tgz
%endif #end if "%{KMP}" == "1"

%package -n %{devel_pname}
Version: %{_version}
# build KMP rpms?
%if "%{KMP}" == "1"
Release: %{_release}%{?_dist}
%else
Release: %{_release}.kver.%{krelver}
%endif
Obsoletes: kernel-ib-devel
Obsoletes: kernel-ib
Obsoletes: mlnx-en
Obsoletes: mlnx_en
Obsoletes: mlnx-en-utils
Obsoletes: kmod-mlnx-en
Obsoletes: mlnx-en-kmp-default
Obsoletes: mlnx-en-kmp-xen
Obsoletes: mlnx-en-kmp-trace
Obsoletes: mlnx-en-doc
Obsoletes: mlnx-en-debuginfo
Obsoletes: mlnx-en-sources
Requires: coreutils
Requires: pciutils
Requires(post): %{_sbindir}/update-alternatives
Requires(postun): %{_sbindir}/update-alternatives
Summary: Infiniband Driver and ULPs kernel modules sources
Group: System Environment/Libraries
%description -n %{devel_pname}
Core, HW and ULPs kernel modules sources
The driver sources are located at: http://www.mellanox.com/downloads/ofed/mlnx-ofa_kernel-25.04-0.6.0.tgz

%package source
Summary: Source of the MLNX_OFED main kernel driver
Group: System Environment/Libraries
%description source
Source of the mlnx-ofa_kernel modules.

You should probably only install this package if you want to view the
sourecs of driver. Use the -devel package if you want to build other
drivers against it.

#
# setup module sign scripts if paths to the keys are given
#
%global WITH_MOD_SIGN %(if ( test -f "$MODULE_SIGN_PRIV_KEY" && test -f "$MODULE_SIGN_PUB_KEY" ); \
	then \
		echo -n '1'; \
	else \
		echo -n '0'; fi)

%if "%{WITH_MOD_SIGN}" == "1"
# call module sign script
%global __modsign_install_post \
    %{_builddir}/$NAME-$VERSION/source/ofed_scripts/tools/sign-modules %{buildroot}/lib/modules/ %{kernel_source default} || exit 1 \
%{nil}

%global __debug_package 1
%global buildsubdir %{_name}-%{version}
# Disgusting hack alert! We need to ensure we sign modules *after* all
# invocations of strip occur, which is in __debug_install_post if
# find-debuginfo.sh runs, and __os_install_post if not.
#
%global __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  %{__modsign_install_post} \
%{nil}

%endif # end of setup module sign scripts
#
%if "%{_vendor}" == "suse"
%debug_package
%endif

%if %{IS_RHEL_VENDOR}
%global __find_requires %{nil}
%endif

# set modules dir
%if %{IS_RHEL_VENDOR}
%if 0%{?fedora}
%global install_mod_dir updates
%else
%global install_mod_dir extra/%{_name}
%endif
%endif

%if "%{_vendor}" == "suse"
%global install_mod_dir updates
%endif

%{!?install_mod_dir: %global install_mod_dir updates}

%prep
%setup -n %{_name}-%{_version}
set -- *
mkdir source
mv "$@" source/
mkdir obj

%build
EXTRA_CFLAGS='-DVERSION=\"%version\"'
%if (0%{?rhel} >= 10)
EXTRA_CFLAGS+=' -fno-exceptions'
%endif
export EXTRA_CFLAGS
export INSTALL_MOD_DIR=%{install_mod_dir}
export CONF_OPTIONS="%{configure_options}"
for flavor in %flavors_to_build; do
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	export LIB_MOD_DIR=/lib/modules/$KVERSION/$INSTALL_MOD_DIR
	rm -rf obj/$flavor
	cp -a source obj/$flavor
	cd $PWD/obj/$flavor
	find compat -type f -exec touch -t 200012201010 '{}' \; || true
	./configure --build-dummy-mods --prefix=%{_prefix} --kernel-version $KVERSION --kernel-sources $KSRC --modules-dir $LIB_MOD_DIR $CONF_OPTIONS %{?_smp_mflags}
	make %{?_smp_mflags} kernel
	make build_py_scripts
	cd -
done

%install
export RECORD_PY_FILES=1
export INSTALL_MOD_PATH=%{buildroot}
export INSTALL_MOD_DIR=%{install_mod_dir}
export NAME=%{name}
export VERSION=%{version}
export PREFIX=%{_prefix}
mkdir -p %{buildroot}/%{_prefix}/src/ofa_kernel/%{_arch}
for flavor in %flavors_to_build; do
	export KSRC=%{kernel_source $flavor}
	export KVERSION=%{kernel_release $KSRC}
	cd $PWD/obj/$flavor
	make install_modules KERNELRELEASE=$KVERSION
	# install script and configuration files
	make install_scripts
	mkdir -p %{_builddir}/src/$NAME/$flavor
	cp -ar include/ %{_builddir}/src/$NAME/$flavor
	cp -ar config* %{_builddir}/src/$NAME/$flavor
	cp -ar compat*  %{_builddir}/src/$NAME/$flavor
	cp -ar ofed_scripts %{_builddir}/src/$NAME/$flavor

	modsyms=`find . -name Module.symvers -o -name Modules.symvers`
	if [ -n "$modsyms" ]; then
		for modsym in $modsyms
		do
			cat $modsym >> %{_builddir}/src/$NAME/$flavor/Module.symvers
		done
	else
		./ofed_scripts/create_Module.symvers.sh
		cp ./Module.symvers %{_builddir}/src/$NAME/$flavor/Module.symvers
	fi
	cp -a %{_builddir}/src/$NAME/$flavor %{buildroot}/%{_prefix}/src/ofa_kernel/%{_arch}/$KVERSION
	# Cleanup unnecessary kernel-generated module dependency files.
	find $INSTALL_MOD_PATH/lib/modules -iname 'modules.*' -exec rm {} \;
	cd -
done

# Set the module(s) to be executable, so that they will be stripped when packaged.
find %{buildroot} \( -type f -name '*.ko' -o -name '*ko.gz' \) -exec %{__chmod} u+x \{\} \;

%if %{IS_RHEL_VENDOR}
%if ! 0%{?fedora}
%{__install} -d %{buildroot}%{_sysconfdir}/depmod.d/
for module in `find %{buildroot}/ -name '*.ko' -o -name '*.ko.gz' | sort`
do
ko_name=${module##*/}
mod_name=${ko_name/.ko*/}
mod_path=${module/*%{_name}}
mod_path=${mod_path/\/${ko_name}}
echo "override ${mod_name} * weak-updates/%{_name}${mod_path}" >> %{buildroot}%{_sysconfdir}/depmod.d/zz01-%{_name}-${mod_name}.conf
echo "override ${mod_name} * extra/%{_name}${mod_path}" >> %{buildroot}%{_sysconfdir}/depmod.d/zz01-%{_name}-${mod_name}.conf
done
%endif
%endif

# copy sources
mkdir -p %{buildroot}/%{_prefix}/src/ofa_kernel-%{version}
cp -a %{_builddir}/%{name}-%{version}/source %{buildroot}/%{_prefix}/src/ofa_kernel-%{version}/source
ln -s ofa_kernel-%{version}/source %{buildroot}/%{_prefix}/src/mlnx-ofa_kernel-%{version}
# Fix path of BACKPORT_INCLUDES
sed -i -e "s@=-I.*backport_includes@=-I/usr/src/ofa_kernel-$VERSION/backport_includes@" %{buildroot}/%{_prefix}/src/ofa_kernel/%{_arch}/%{KVERSION}/configure.mk.kernel || true
rm -rf %{_builddir}/src

INFO=${RPM_BUILD_ROOT}/etc/infiniband/info
/bin/rm -f ${INFO}
mkdir -p ${RPM_BUILD_ROOT}/etc/infiniband
touch ${INFO}

cat >> ${INFO} << EOFINFO
#!/bin/bash

echo prefix=%{_prefix}
echo Kernel=%{KVERSION}
echo
echo "Configure options: %{configure_options}"
echo
EOFINFO

chmod +x ${INFO} > /dev/null 2>&1

%if "%{WITH_SYSTEMD}" == "1"
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}/etc/systemd/system
install -m 0644 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/openibd.service %{buildroot}%{_unitdir}
install -m 0644 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/mlnx_interface_mgr\@.service %{buildroot}/etc/systemd/system
%endif

install -d %{buildroot}/bin
install -m 0755 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/mlnx_conf_mgr.sh %{buildroot}/bin/
%if "%{WINDRIVER}" == "0" && "%{BLUENIX}" == "0"
install -m 0755 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/mlnx_interface_mgr.sh %{buildroot}/bin/
%else
# Wind River and Mellanox Bluenix are rpm based, however, interfaces management is done in Debian style
install -d %{buildroot}/usr/sbin
install -m 0755 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/mlnx_interface_mgr_deb.sh %{buildroot}/bin/mlnx_interface_mgr.sh
install -m 0755 %{_builddir}/$NAME-$VERSION/source/ofed_scripts/net-interfaces %{buildroot}/usr/sbin
%endif

# Install ibroute utilities
# TBD: move these utilities into standalone package
install -d %{buildroot}%{_sbindir}

%if %{build_ipoib}
case $(uname -m) in
	i[3-6]86)
	# Decrease send/receive queue sizes on 32-bit arcitecture
	echo "options ib_ipoib send_queue_size=64 recv_queue_size=128" >> %{buildroot}/etc/modprobe.d/ib_ipoib.conf
	;;
esac
%endif

%clean
rm -rf %{buildroot}


%if "%{KMP}" != "1"
%post -n %{non_kmp_pname}
/sbin/depmod %{KVERSION}
# W/A for OEL6.7/7.x inbox modules get locked in memory
# in dmesg we get: Module mlx4_core locked in memory until next boot
if (grep -qiE "Oracle.*(6.([7-9]|10)| 7)" /etc/issue /etc/*release* 2>/dev/null); then
	/sbin/dracut --force
fi

%postun -n %{non_kmp_pname}
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
	/sbin/depmod %{KVERSION}
	# W/A for OEL6.7/7.x inbox modules get locked in memory
	# in dmesg we get: Module mlx4_core locked in memory until next boot
	if (grep -qiE "Oracle.*(6.([7-9]|10)| 7)" /etc/issue /etc/*release* 2>/dev/null); then
		/sbin/dracut --force
	fi
fi
%endif # end KMP=1

%post -n %{utils_pname}
if [ $1 -eq 1 ]; then # 1 : This package is being installed
%if "%{WITH_SYSTEMD}" == "1"
export SYSTEMCTL_SKIP_SYSV=1
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
/usr/bin/systemctl enable openibd >/dev/null  2>&1 || true
cat /proc/sys/kernel/random/boot_id 2>/dev/null | sed -e 's/-//g' > /var/run/openibd.bootid || true
test -s /var/run/openibd.bootid || echo manual > /var/run/openibd.bootid || true
%endif

# Comment core modules loading hack
if [ -e /etc/modprobe.conf.dist ]; then
	sed -i -r -e 's/^(\s*install ib_core.*)/#MLX# \1/' /etc/modprobe.conf.dist
	sed -i -r -e 's/^(\s*alias ib.*)/#MLX# \1/' /etc/modprobe.conf.dist
fi

%if %{build_ipoib}
if [ -e /etc/modprobe.d/ipv6 ]; then
	sed -i -r -e 's/^(\s*install ipv6.*)/#MLX# \1/' /etc/modprobe.d/ipv6
fi
%endif

# Update limits.conf (but not for Containers)
if [ ! -e "/.dockerenv" ] && ! (grep -q docker /proc/self/cgroup 2>/dev/null); then
	if [ -e /etc/security/limits.conf ]; then
		LIMITS_UPDATED=0
		if ! (grep -qE "soft.*memlock" /etc/security/limits.conf 2>/dev/null); then
			echo "* soft memlock unlimited" >> /etc/security/limits.conf
			LIMITS_UPDATED=1
		fi
		if ! (grep -qE "hard.*memlock" /etc/security/limits.conf 2>/dev/null); then
			echo "* hard memlock unlimited" >> /etc/security/limits.conf
			LIMITS_UPDATED=1
		fi
		if [ $LIMITS_UPDATED -eq 1 ]; then
			echo "Configured /etc/security/limits.conf"
		fi
	fi
fi

# Make IPoIB interfaces be unmanaged on XenServer
if (grep -qi xenserver /etc/issue /etc/*-release 2>/dev/null); then
	IPOIB_PNUM=$(lspci -d 15b3: 2>/dev/null | wc -l 2>/dev/null)
	IPOIB_PNUM=$(($IPOIB_PNUM * 2))
	for i in $(seq 1 $IPOIB_PNUM)
	do
		uuid=$(xe pif-list 2>/dev/null | grep -B2 ib${i} | grep uuid | cut -d : -f 2 | sed -e 's/ //g')
		if [ "X${uuid}" != "X" ]; then
			xe pif-forget uuid=${uuid} >/dev/null 2>&1 || true
		fi
	done
fi

fi # 1 : closed
# END of post

%preun -n %{utils_pname}
%if "%{WITH_SYSTEMD}" == "1"
export SYSTEMCTL_SKIP_SYSV=1
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
          /usr/bin/systemctl disable openibd >/dev/null  2>&1 || true
fi
%endif

%postun -n %{utils_pname}
%if "%{WITH_SYSTEMD}" == "1"
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%endif

# Uncomment core modules loading hack
if [ -e /etc/modprobe.conf.dist ]; then
	sed -i -r -e 's/^#MLX# (.*)/\1/' /etc/modprobe.conf.dist
fi

%if %{build_ipoib}
if [ -e /etc/modprobe.d/ipv6 ]; then
	sed -i -r -e 's/^#MLX# (.*)/\1/' /etc/modprobe.d/ipv6
fi
%endif

#end of post uninstall

%post -n %{devel_pname}
if [ -d "%{_prefix}/src/ofa_kernel/default" -a $1 -gt 1 ]; then
	touch %{_prefix}/src/ofa_kernel/%{_arch}/%{KVERSION}.missing_link
	# Will run update-alternatives in posttrans
else
	update-alternatives --install \
		%{_prefix}/src/ofa_kernel/default \
		ofa_kernel_headers \
		%{_prefix}/src/ofa_kernel/%{_arch}/%{KVERSION} \
		20
fi

%posttrans -n %{devel_pname}
symlink="%{_prefix}/src/ofa_kernel/default"
# Should only be used for upgrading from pre-5.5-0.2.6.0 packages:
# At the time of upgrade there was still a directory, so postpone
# generating the alternative symlink to that point:
for flag_file in %{_prefix}/src/ofa_kernel/*/*.missing_link; do
	dir=${flag_file%.missing_link}
	if [ ! -d "$dir" ]; then
		# Directory is no longer there. Nothing left to handle
		rm -f "$flag_file"
		continue
	fi
	if [ -d "$symlink" ]; then
		echo "%{devel_pname}-%{version}: $symlink is still a non-empty directory. Deleting in preparation for a symlink."
		rm -rf "$symlink"
	fi
	update-alternatives --install \
		"$symlink" \
		ofa_kernel_headers \
		"$dir" \
		20
	rm -f "$flag_file"
done

%postun -n %{devel_pname}
update-alternatives --remove \
	ofa_kernel_headers \
	%{_prefix}/src/ofa_kernel/%{_arch}/%{KVERSION} \

%files -n %{utils_pname}
%defattr(-,root,root,-)
%doc source/ofed_scripts/82-net-setup-link.rules source/ofed_scripts/vf-net-link-name.sh
%if "%{KMP}" == "1"
%if %{IS_RHEL_VENDOR}
%endif # end rh
%endif # end KMP=1
%dir /etc/infiniband
%config(noreplace) /etc/infiniband/openib.conf
%config(noreplace) /etc/infiniband/mlx5.conf
/etc/infiniband/info
/etc/init.d/openibd
%if "%{WITH_SYSTEMD}" == "1"
%{_unitdir}/openibd.service
/etc/systemd/system/mlnx_interface_mgr@.service
%endif
/lib/udev/sf-rep-netdev-rename
/lib/udev/auxdev-sf-netdev-rename
/usr/sbin/setup_mr_cache.sh
%_datadir/mlnx_ofed/mlnx_bf_assign_ct_cores.sh
%_datadir/mlnx_ofed/mlnx_drv_ctl
%_datadir/mlnx_ofed/mod_load_funcs
%config(noreplace) /etc/modprobe.d/mlnx.conf
%config(noreplace) /etc/modprobe.d/mlnx-bf.conf
%{_sbindir}/*
/lib/udev/rules.d/83-mlnx-sf-name.rules
/lib/udev/rules.d/90-ib.rules
/bin/mlnx_interface_mgr.sh
/bin/mlnx_conf_mgr.sh
%if "%{WINDRIVER}" == "1" || "%{BLUENIX}" == "1"
/usr/sbin/net-interfaces
%endif
%if %{build_ipoib}
%config(noreplace) /etc/modprobe.d/ib_ipoib.conf
%endif
%if %{build_mlx5}
%{_sbindir}/ibdev2netdev
%endif

%if "%{KMP}" != "1"
%files -n %{non_kmp_pname}
/lib/modules/%{KVERSION}/%{install_mod_dir}/
%if %{IS_RHEL_VENDOR}
%if ! 0%{?fedora}
%config(noreplace) %{_sysconfdir}/depmod.d/zz01-%{_name}-*.conf
%endif
%endif
%endif

%files -n %{devel_pname}
%defattr(-,root,root,-)
%dir %{_prefix}/src/ofa_kernel
%dir %{_prefix}/src/ofa_kernel/%{_arch}
%ghost %{_prefix}/src/ofa_kernel/default
%{_prefix}/src/ofa_kernel/%{_arch}/[0-9]*

%files source
%defattr(-,root,root,-)
%dir %{_prefix}/src/ofa_kernel-%{version}
%{_prefix}/src/ofa_kernel-%version/source
%{_prefix}/src/mlnx-ofa_kernel-%version

%changelog
* Thu Jun 18 2015 Alaa Hleihel <alaa@mellanox.com>
- Renamed kernel-ib package to mlnx-ofa_kernel-modules
* Thu Apr 10 2014 Alaa Hleihel <alaa@mellanox.com>
- Add QoS utils.
* Thu Mar 13 2014 Alaa Hleihel <alaa@mellanox.com>
- Use one spec for KMP and non-KMP OS's.
* Tue Apr 24 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Remove FC support
* Tue Mar 6 2012 Vladimir Sokolovsky <vlad@mellanox.com>
- Add weak updates support
* Wed Jul 6 2011 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Add KMP support
* Mon Oct 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Add mlx4_fc and mlx4_vnic support
* Mon May 10 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Support install macro that removes RPM_BUILD_ROOT
* Thu Feb 4 2010 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added ibdev2netdev script
* Mon Sep 8 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added nfsrdma support
* Wed Aug 13 2008 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added mlx4_en support
* Tue Aug 21 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Added %build macro
* Sun Jan 28 2007 Vladimir Sokolovsky <vlad@mellanox.co.il>
- Created spec file for kernel-ib
