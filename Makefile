PROG=		ankh
SRCS=		ankh.c

CFLAGS+=	-Wall -Werror
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-I/usr/local/include

LDADD=		-L/usr/local/lib -lsodium

BINDIR=		/usr/local/bin
MANDIR=		/usr/local/man/man

mode=		1
secret=		secret.passphrase
testsize=	bs=$$(($$RANDOM % 1024 + 1)) count=$$(($$RANDOM % 8192 + 1024))

test: ${PROG}
	dd if=/dev/random of=foo.bin ${testsize}
	sha256 foo.bin | tee SHA256
	tr -cd [:graph:] < /dev/random | fold -bw 40 | head -1 | tee ${secret}
	${PROG} -K -m ${mode} -k ${secret} < foo.bin > bar.bin
	${PROG} -K -d -m ${mode} -k ${secret} < bar.bin > foo.bin
	sha256 -c SHA256
	${PROG} -G -p ankh.pub -s ankh.sec -m ${mode} -k ${secret}
	${PROG} -B -p ankh.pub -k ${secret} < foo.bin > bar.bin
	${PROG} -B -p ankh.pub -k ${secret} -s ankh.sec -d < bar.bin > foo.bin
	sha256 -c SHA256

.include <bsd.prog.mk>
