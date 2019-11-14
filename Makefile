
ETCDIR = /etc/pdns
BINDIR = /usr/sbin
DOCDIR = /usr/share/doc/pdns-dynrev

INSTALL = install
MKDIR_P = mkdir -p -m 755

all: 
	@echo "Type 'make install'"

clean: 


install: 
	$(MKDIR_P) $(DESTDIR)$(ETCDIR)
	$(MKDIR_P) $(DESTDIR)$(BINDIR)
	$(MKDIR_P) $(DESTDIR)$(DOCDIR)
	$(INSTALL) -pm 644 dynrev.yml $(DESTDIR)$(ETCDIR)/dynrev.yml.example
	$(INSTALL) -pm 644 README.md $(DESTDIR)$(DOCDIR)/README
	$(INSTALL) -pm 755 pdns-dynamic-reverse-backend.py $(DESTDIR)$(BINDIR)/pdns-dynamic-reverse-backend.py
	
