#!/bin/bash

function wrapper_has_changes() {
	plugin="$1"
	version="$2"

	git diff --quiet "wrappers/$plugin/v$version"...HEAD -- "wrappers/$plugin"
	ret=$?

	if (( ret == 1 )); then
		return 0
	elif (( ret == 0 )); then
		return 1
	else
		echo "unknown exit status from diff: $ret" 1>&2
		exit 1
	fi
}

function bump_minor() {
	version="$1"
	major="$(grep -io '^[0-9]*\.' <<< "$version" | sed 's/\.//g')"
	minor="$(grep -io '\.[0-9]*\.' <<< "$version" | sed 's/\.//g')"
	echo "$major.$(( minor + 1 )).0"
}

function wrapper_last_version() {
	plugin="$1"
	git tag --list "wrappers/$plugin/v*" --sort=authordate | tail -n 1 | sed "s/^wrappers\/$plugin\/v//g"
}

function last_version() {
	git tag --list 'v*' --sort=authordate | tail -n 1 | sed 's/^v//g'
}

if [ -z "$ORIGIN" ]; then
	if [ "$1" == "apply" ]; then
		echo "missing environment variable \$ORIGIN" 1>&2
		exit 1
	fi
fi

last_tag="$(last_version)"
new_tag="$(bump_minor "$last_tag")"

echo "go-kms-wrapping: v$last_tag -> v$new_tag"

if [ "$1" == "apply" ]; then
	git tag "v$new_tag"
	git push "$ORIGIN" "v$new_tag"
fi

for plugin_dir in wrappers/*; do
	if [ ! -d "$plugin_dir" ]; then
		echo "skipping non-directory $plugin_dir"
	fi

	plugin="$(sed 's#^wrappers/##g' <<< "$plugin_dir")"
	plugin_last_tag="$(wrapper_last_version "$plugin")"

	if [ -z "$plugin_last_tag" ]; then
		plugin_last_tag="(new)"
		plugin_new_tag="v2.0.0"

		if [ "$1" == "apply" ]; then
			git tag "wrappers/$plugin/v$plugin_new_tag"
			git push "$ORIGIN" "wrappers/$plugin/v$plugin_new_tag"
		fi

		continue
	fi

	if wrapper_has_changes "$plugin" "$plugin_last_tag"; then
		plugin_new_tag="$(bump_minor "$plugin_last_tag")"
		echo "go-kms-wrapping/wrappers/$plugin v$plugin_last_tag -> v$plugin_new_tag"

		if [ "$1" == "apply" ]; then
			git tag "wrappers/$plugin/v$plugin_new_tag"
			git push "$ORIGIN" "wrappers/$plugin/v$plugin_new_tag"
		fi
	fi
done

if [ "$1" != "apply" ]; then
	echo "Use '$0 apply' to apply and push changes" 1>&2
	exit 1
fi
