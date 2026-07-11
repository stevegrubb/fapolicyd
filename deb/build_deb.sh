#! /bin/bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
top_dir=$(cd -- "${script_dir}/.." && pwd)
version=$(sed -n 's/^AC_INIT(\[fapolicyd\],\[\([^]]*\)\].*/\1/p' \
	"${top_dir}/configure.ac")
if [ "${version}" = "" ] ; then
	echo "Unable to determine fapolicyd version" >&2
	exit 1
fi

dist_dir="fapolicyd-${version}"
source_archive="${top_dir}/${dist_dir}.tar.gz"
build_archive="${script_dir}/${dist_dir}.tar.gz"
source_dir="${script_dir}/${dist_dir}"

# make dist otherwise reuses an existing archive, which may not match the
# current source tree.
rm -f "${source_archive}"
make -C "${top_dir}" dist
if [ ! -f "${source_archive}" ] ; then
	echo "Expected distribution archive ${source_archive} was not created" >&2
	exit 1
fi

# Recreate only this version's packaging tree so repeated runs cannot select
# stale archives or unpack over the previous debmake output.
rm -rf "${source_dir}"
cp "${source_archive}" "${build_archive}"
tar -xzf "${build_archive}" -C "${script_dir}"
if [ ! -d "${source_dir}" ] ; then
	echo "Expected distribution directory ${source_dir} was not extracted" >&2
	exit 1
fi


(
	cd "${source_dir}"

	# Ugly work around for INSTALL.tmp
	# Need to figure out proper fix.
	mv INSTALL INSTALL.tmp
)

tar -C "${script_dir}" -czf "${build_archive}" "${dist_dir}"
cd "${source_dir}"

debmake

cp "${script_dir}/rules" debian/
cp "${script_dir}/postinst" debian/
cp "${script_dir}/README.Debian" debian/

debuild
