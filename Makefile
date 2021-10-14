# Copyright (c) 2019-2021 Sine Nomine Associates

.PHONY: help init lint test docs preview build install clean distclean

PYTHON := /usr/bin/python3
VERSION := $(strip $(subst version:,,$(shell grep version: galaxy.yml)))
UPDATE := --force --pre
MODULES := $(wildcard plugins/modules/openafs_*.py)
EXTRACTED := $(patsubst plugins/modules/%.py,docs/source/modules/%.rst,$(MODULES))
ACPATH := $(realpath $(CURDIR)/../../..)

help:
	@echo "usage: make <target>"
	@echo "targets:"
	@echo "  venv        install virtualenv"
	@echo "  lint        run lint checks"
	@echo "  test        run unit and molecule tests"
	@echo "  docs        generate documentation"
	@echo "  build       build openafs collection"
	@echo "  install     install openafs collection"
	@echo "  reset       reset molecule temporary directories"
	@echo "  clean       remove generated files"
	@echo "  distclean   remove generated files and virtualenv"

.venv/bin/activate:
	test -d .venv || $(PYTHON) -m venv .venv
	.venv/bin/pip install -U pip
	.venv/bin/pip install wheel
	.venv/bin/pip install molecule[ansible] molecule-vagrant molecule-virtup \
                          python-vagrant ansible-lint flake8 pyflakes pytest \
                          sphinx sphinx-rtd-theme ansible-doc-extractor
	touch .venv/bin/activate

init venv: .venv/bin/activate

docs/source/modules/%.rst: plugins/modules/%.py
	mkdir -p docs/source/modules
	ANSIBLE_COLLECTIONS_PATHS=$(ACPATH) \
	ansible-doc-extractor docs/source/modules $<

doc docs: $(EXTRACTED)
	$(MAKE) -C docs html

preview: docs
	xdg-open docs/build/html/index.html

builds/openafs_contrib-openafs-$(VERSION).tar.gz:
	mkdir -p builds
	ansible-galaxy collection build --output-path builds .

build: builds/openafs_contrib-openafs-$(VERSION).tar.gz

install: build
	ansible-galaxy collection install $(UPDATE) builds/openafs_contrib-openafs-$(VERSION).tar.gz

lint:
	flake8 --ignore E501 plugins/modules/*.py
	pyflakes plugins/modules/*.py
	$(MAKE) -C roles/openafs_krbserver lint
	$(MAKE) -C roles/openafs_krbclient lint
	$(MAKE) -C roles/openafs_common lint
	$(MAKE) -C roles/openafs_devel lint
	$(MAKE) -C roles/openafs_server lint
	$(MAKE) -C roles/openafs_client lint

test: test-modules test-roles test-playbooks

test-modules:
	$(MAKE) -C tests test

test-roles:
	$(MAKE) -C roles/openafs_krbserver test
	$(MAKE) -C roles/openafs_krbclient test
	$(MAKE) -C roles/openafs_common test
	$(MAKE) -C roles/openafs_devel test
	$(MAKE) -C roles/openafs_server test
	$(MAKE) -C roles/openafs_client test

test-playbooks:
	$(MAKE) -C tests/playbooks test

reset:
	for r in roles/*; do $(MAKE) -C $$r reset; done
	$(MAKE) -C tests/playbooks reset

clean:
	rm -rf builds
	rm -rf docs/build
	$(MAKE) -C tests clean

distclean: clean
	rm -rf .venv
