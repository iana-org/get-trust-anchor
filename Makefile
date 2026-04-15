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
	(. $(VENV)/bin/activate; $(MAKE) regress_offline regress_online)

regress_offline:
	python -m py_compile get_trust_anchor/cli.py

regress_online:
	python -m get_trust_anchor
	diff -u regress/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u regress/ksk-as-ds.txt ksk-as-ds.txt

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ get_trust_anchor/__pycache__ *.pyc

realclean: clean
	rm -rf $(VENV)
