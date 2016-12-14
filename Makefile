VENV2=		venv2
VENV3=		venv3

PYTHON2=	python2.7
PYTHON3=	python3.5

DISTDIRS=	*.egg-info build dist
TMPFILES=	ksk-as-{dnskey,ds}.txt \


all:

lint:
	$(VENV3)/bin/pylint --reports=no *.py

wheel:
	python setup.py bdist_wheel

venv: $(VENV2) $(VENV3)

$(VENV2):
	virtualenv -p $(PYTHON2) $(VENV2)

$(VENV3):
	virtualenv -p $(PYTHON3) $(VENV3)

test: test2 test3

test2: $(VENV2)
	(. $(VENV2)/bin/activate; $(MAKE) regress2_offline regress2_online)

test3: $(VENV3)
	(. $(VENV3)/bin/activate; $(MAKE) regress3_offline regress3_online)

regress2_offline:
	python -m py_compile get_trust_anchor.py

regress2_online:
	python get_trust_anchor.py
	diff -u regress/ksk-as-dnskey.txt ksk-as-dnskey.txt
	diff -u regress/ksk-as-ds.txt ksk-as-ds.txt

regress3_online: regress2_online
	python -m py_compile get_trust_anchor.py

regress3_offline:
	python -m py_compile get_trust_anchor.py

clean:
	rm -fr $(DISTDIRS)
	rm -f $(TMPFILES)
	rm -fr __pycache__ *.pyc

realclean: clean
	rm -rf $(VENV2) $(VENV3)
