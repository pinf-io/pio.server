#!/bin/bash -e

MON_VERSION=$1

BASE_PATH="$(pwd)"
DEP_BASE_PATH="$BASE_PATH/../../../packages"

if [ ! -d $DEP_BASE_PATH ]; then
	mkdir -p $DEP_BASE_PATH
fi
cd $DEP_BASE_PATH
	if [ ! -d "mon-$MON_VERSION" ]; then
		echo "Installing mon ($MON_VERSION)"

		TMP_DIR="mon-$MON_VERSION-$(date +%s%N)"
		mkdir $TMP_DIR
		cd $TMP_DIR

		curl -L# https://github.com/visionmedia/mon/archive/$MON_VERSION.tar.gz | tar zx --strip 1
		make

		# TODO: Make sure we fail if these calls fail.
		echo "mon version: "$(./mon --version)

		cd ..

		mv $TMP_DIR mon-$MON_VERSION
	fi
exit 0

main $@
