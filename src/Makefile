OBJECTS = cf.o folder.o imap.o log.o main.o tcp.o utils.o deliver.o deliver_mbox.o deliver_pipeto.o deliver_maildir.o auth.o base64.o md5.o secrets.o
# For OpenSSL use.
CFLAGS += -Wall -D_USE_OPENSSL -g -DDEBUG
# If you don't have OpenSSL:
#CFLAGS += -Wall -g -DDEBUG
# If your OpenSSL lives somewhere else:
#CFLAGS += -Wall -g -D_USE_OPENSSL -I/OpenSSL/include/directory
#LDFLAGS += -lssl 
# Without OpenSSL, remove the LDFLAGS line entirely.
# With debugging:
LDFLAGS += -lssl -g -lefence
# Change the following line if you want to install somewhere different.
PREFIX = /usr/local/

all: imapget

imapget: ${OBJECTS}
	gcc -o imapget ${OBJECTS} ${LDFLAGS}

clean:
	rm -f *.o imapget

install: all
	install -d ${PREFIX}/bin
	install imapget ${PREFIX}/bin
