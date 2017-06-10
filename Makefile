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
	tr -cd [:graph:] < /dev/random | fold -bw 20 | head -1 | tee ${secret}
	${PROG} -K -v -i foo.bin -o bar.bin -m ${mode} -k ${secret}
	${PROG} -K -v -d -i bar.bin -o foo.bin -m ${mode} -k ${secret}
	sha256 -c SHA256
	${PROG} -G -v -p public.key -s secret.key -m ${mode} -k ${secret}

.include <bsd.prog.mk>
