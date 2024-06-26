srpm:
	dnf install -y git
	git config --global --add safe.directory ${PWD}
	./build.sh --with-timestamp --with-commit-id --with-deps srpm
	if [[ "${outdir}" != "" ]]; then \
	    mv ${HOME}/build/jss/SRPMS/* ${outdir}; \
	fi
