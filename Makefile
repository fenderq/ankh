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
#MANDIR=		/usr/local/man/man
NOMAN=		noman

infile=		foo.bin
mode=		1
outfile=	bar.bin
pubkey=		ankh.pub
seckey=		ankh.sec
secret=		secret.passphrase
testsize=	bs=$$(($$RANDOM % 8192 + 1)) count=$$(($$RANDOM % 8192 + 1024))

test: ${PROG}
	# generate random sample data
	dd if=/dev/random of=${infile} ${testsize}
	sha256 ${infile} | tee SHA256
	# generate random passphrase
	tr -cd [:graph:] < /dev/random | fold -bw 40 | head -1 | tee ${secret}
	# test secret key
	${PROG} -K -m ${mode} -k ${secret} < ${infile} > ${outfile}
	${PROG} -K -d -m ${mode} -k ${secret} < ${outfile} > ${infile}
	sha256 -c SHA256
	# generate key pair
	${PROG} -G -p ${pubkey} -s ${seckey} -m ${mode} -k ${secret}
	# test sealed box
	${PROG} -B -p ${pubkey} -k ${secret} < ${infile} > ${outfile}
	${PROG} -B -p ${pubkey} -k ${secret} -s ${seckey} -d \
	    < ${outfile} > ${infile}
	sha256 -c SHA256

.include <bsd.prog.mk>
