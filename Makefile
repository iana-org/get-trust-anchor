VENV=		venv

DISTDIRS=	*.egg-info build dist
TMPFILES=	ksk-as-{dnskey,ds}.txt \


all:

lint:
	$(VENV)/bin/pylint --reports=no get_trust_anchor/

wheel:
	python -m build

venv: $(VENV)

$(VENV):
	python3 -m venv $(VENV)

test: $(VENV)
	$(VENV)/bin/pip install -e ".[test]"
	$(VENV)/bin/pytest

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ get_trust_anchor/__pycache__ tests/__pycache__ *.pyc .pytest_cache

realclean: clean
	rm -rf $(VENV)
