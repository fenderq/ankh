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

alice_pk=	alice.pub
alice_sk=	alice.sec
bob_pk=		bob.pub
bob_sk=		bob.sec
ciphertext=	ciphertext.ankh
mode=		1
passwd=		secret.passphrase
plaintext=	plaintext.bin
testsize=	bs=$$(($$RANDOM % 8192 + 1)) count=$$(($$RANDOM % 8192 + 1024))

test: ${PROG}
	# generate random sample data
	dd if=/dev/random of=${plaintext} ${testsize}
	sha256 ${plaintext} | tee SHA256
	# generate random passphrase
	tr -cd [:graph:] < /dev/random | fold -bw 40 | head -1 | tee ${passwd}
	# generate key pairs
	./${PROG} -G -p ${alice_pk} -s ${alice_sk} -m ${mode} -k ${passwd}
	./${PROG} -G -p ${bob_pk} -s ${bob_sk} -m ${mode} -k ${passwd}
	# test public key
	./${PROG} -P -p ${bob_pk} -s ${alice_sk} -k ${passwd}\
	    < ${plaintext} > ${ciphertext}
	./${PROG} -P -p ${alice_pk} -s ${bob_sk} -k ${passwd} -d\
	    < ${ciphertext} > ${plaintext}
	sha256 -c SHA256
	# test sealed box
	./${PROG} -B -p ${alice_pk} -k ${passwd} < ${plaintext} > ${ciphertext}
	./${PROG} -B -p ${alice_pk} -s ${alice_sk} -k ${passwd} -d\
	    < ${ciphertext} > ${plaintext}
	sha256 -c SHA256
	# test secret key
	./${PROG} -S -m ${mode} -k ${passwd} < ${plaintext} > ${ciphertext}
	./${PROG} -S -d -m ${mode} -k ${passwd} < ${ciphertext} > ${plaintext}
	sha256 -c SHA256

.include <bsd.prog.mk>
