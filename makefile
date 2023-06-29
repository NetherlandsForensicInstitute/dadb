SHELL := /bin/bash

.PHONY: help
help:
	@echo
	@echo "makefile targets"
	@echo "----------------"
	@echo "  make wheel       - create python3 wheel"
	@echo "  make clean       - remove build data and compiled files"
	@echo "  make install     - install via pip3"
	@echo "  make uninstall   - uninstall via pip3"
	@echo ""

.PHONY: wheel
wheel:
	python3 setup.py bdist_wheel
	rm -rf dadb.egg-info
	rm -rf build
	rm -rf dadb/__pycache__

.PHONY: clean
clean:
	rm -rf dadb.egg-info
	rm -rf build
	rm -rf dadb/__pycache__

.PHONY: install
install:
	pip3 install .

.PHONY: uninstall
uninstall:
	pip3 uninstall dadb

