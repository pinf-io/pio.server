#!/bin/bash -e

NODE_VERSION=$1

if hash curl 2>/dev/null; then
	FETCH="curl -sSOL"
elif hash wget 2>/dev/null; then
	FETCH="wget -nc"
else
	echo "ERROR: No 'curl' nor 'wget' command found!" >&2
	exit 1
fi

if ! hash make 2>/dev/null; then
	sudo apt-get -y install make
fi
if ! hash g++ 2>/dev/null; then
	sudo apt-get -y install g++
fi

BASE_PATH="$(pwd)"
DEP_BASE_PATH="$BASE_PATH/../../../packages"

main() {

	local uname="$(uname -a)"
	local os=
	local arch="$(uname -m)"
	case "$uname" in
		Linux\ *) os=linux ;;
		Darwin\ *) os=darwin ;;
		SunOS\ *) os=sunos ;;
		FreeBSD\ *) os=freebsd ;;
		esac
	case "$uname" in
		*x86_64*) arch=x64 ;;
		*i*86*) arch=x86 ;;
		*armv6l*) arch=arm-pi ;;
		esac  
	if [ $os != "linux" ] && [ $os != "darwin" ]; then
		echo "ERROR: Unsupported Platform: $os $arch" 1>&2
		exit 1
	fi
	if [ $arch != "x64" ] && [ $arch != "x86" ]; then
		echo "ERROR: Unsupported Architecture: $os $arch" 1>&2
		exit 1
	fi

	if [ ! -d $DEP_BASE_PATH ]; then
		mkdir -p $DEP_BASE_PATH
	fi
	cd $DEP_BASE_PATH
		if [ ! -d "node-$NODE_VERSION" ]; then
			echo "Installing NodeJS ($NODE_VERSION) and NPM"
			if [ ! -f "node-$NODE_VERSION-$os-$arch.tar.gz" ]; then
				$FETCH http://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-$os-$arch.tar.gz
			fi
			tar xfz node-$NODE_VERSION-$os-$arch.tar.gz
			# TODO: Make sure we fail if these calls fail.
			echo "Node version: "$(node-$NODE_VERSION-$os-$arch/bin/node --version)
			echo "NPM version: "$(node-$NODE_VERSION-$os-$arch/bin/npm --version)
			mv node-$NODE_VERSION-$os-$arch node-$NODE_VERSION
		fi
	exit 0
}

main $@
