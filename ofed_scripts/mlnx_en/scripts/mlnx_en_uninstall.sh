# MLNX_EN uninstall script
if ( grep -E "Ubuntu|Debian" /etc/issue > /dev/null 2>&1); then
	apt-get remove -y `dpkg --list 2>/dev/nulll | grep -E "mstflint|mlnx" | awk '{print $2}' 2>/dev/nulll` > /dev/null
	apt-get remove -y --purge mlnx-en-utils > /dev/null
else
	rpm -e `rpm -qa 2>/dev/nulll | grep -E "mstflint|mlnx.en|mlx.*en" | grep -v '^kernel-module'` > /dev/null
fi

/bin/rm -f $0

echo "MLNX_EN uninstall done"
