/*
 * Copyright (c) 2017 Steven Roberts <sroberts@fenderq.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <readpassphrase.h>
#include <unistd.h>

#include <sodium.h>

#define BUFSIZE 1024 * 1024
#define DEFAULT_MODE 2
#define MAX_LINE 4096
#define MAX_PASSWD 1024
#define MAX_STRING 256
#define VERSION "2.0.0"

enum command {
	CMD_UNDEFINED,
	CMD_CHANGE_PASSPHRASE,
	CMD_GENERATE_KEY_PAIR,
	CMD_HASH,
	CMD_PUBLIC_KEY,
	CMD_SEALED_BOX,
	CMD_SECRET_KEY,
	CMD_SIGNATURE,
	CMD_VERSION
};

struct cipher_info {
	FILE *fin;
	FILE *fout;
	int enc;
	unsigned char key[crypto_secretbox_KEYBYTES];
};

extern char *__progname;
extern char *optarg;

size_t memlimit;
unsigned long long opslimit;
int verbose;

__dead void usage(void);

static int	 cipher(struct cipher_info *);
static int	 generate_key_pair(char *, char *, char *, char *);
static int	 read_key(char *, size_t);
static int	 read_keyfile(char *, char *, size_t);
static int	 secret_key(char *, char *, int);
static void	 kdf(uint8_t *, int, int, uint8_t *);
static void	 print_value(char *, unsigned char *, int);
static void	 set_mode(int);
static char	*str_time(char *, size_t, time_t);

int
main(int argc, char *argv[])
{
	char *comment;
	char *infile;
	char *keyfile;
	char *outfile;
	char *pubkey;
	char *seckey;
	char ch;
	const char *ep;
	enum command cmd;
	int dflag;
	int mode;

	cmd = CMD_UNDEFINED;
	comment = NULL;
	dflag = 0;
	infile = NULL;
	keyfile = NULL;
	mode = DEFAULT_MODE;
	outfile = NULL;
	pubkey = NULL;
	seckey = NULL;
#if 0
	if (pledge("cpath rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");
#endif

	if (sodium_init() == -1)
		errx(1, "libsodium init error");

	while ((ch = getopt(argc, argv, "BCGHKPSVc:di:k:m:o:p:s:v")) != -1) {
		switch (ch) {
		case 'B':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_SEALED_BOX;
			break;
		case 'C':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_CHANGE_PASSPHRASE;
			break;
		case 'G':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_GENERATE_KEY_PAIR;
			break;
		case 'H':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_HASH;
			break;
		case 'K':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_SECRET_KEY;
			break;
		case 'P':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_PUBLIC_KEY;
			break;
		case 'S':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_SIGNATURE;
			break;
		case 'V':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_VERSION;
			break;
		case 'c':
			comment = optarg;
			break;
		case 'd':
			dflag = 1;
			break;
		case 'i':
			infile = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		case 'm':
			mode = strtonum(optarg, 1, 3, &ep);
			if (ep != NULL)
				errx(1, "mode %s", ep);
			break;
		case 'p':
			pubkey = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 's':
			seckey = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	set_mode(mode);

	switch (cmd) {
	case CMD_UNDEFINED:
		usage();
		break;
	case CMD_CHANGE_PASSPHRASE:
		break;
	case CMD_GENERATE_KEY_PAIR:
		generate_key_pair(pubkey, seckey, keyfile, comment);
		break;
	case CMD_HASH:
		break;
	case CMD_PUBLIC_KEY:
		break;
	case CMD_SEALED_BOX:
		break;
	case CMD_SECRET_KEY:
		secret_key(infile, outfile, dflag ? 0 : 1);
		break;
	case CMD_SIGNATURE:
		break;
	case CMD_VERSION:
		printf("%s %s (libsodium %s)\n", __progname, VERSION,
		    sodium_version_string());
		break;
	}

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	/*
		ankh B [sealed box] -d -p -s -i -o
		ankh C [change passphrase] -k -m -s
		ankh G [generate key pair] -c -k -m -p -s
		ankh H [hash] -i -o
		ankh K [secret key] -d -k -m -i -o
		ankh P [public key] -d -p -s -i -o
		ankh S [signature] -p -s -i -o
		ankh V [version]
	 */
	fprintf(stderr, "usage: %s [-dv] [-m mode] infile outfile\n",
	    __progname);
	exit(EXIT_FAILURE);
}

static int
save_pubkey(char *fname, unsigned char *k, size_t kz, char *comment)
{
	FILE *fp;
	char *hex;
	char now[MAX_STRING];
	size_t hexsize;
	time_t t;

	hexsize = kz * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, k, kz);
	if ((fp = fopen(fname, "w")) == NULL)
		err(1, "%s", fname);
	time(&t);
	str_time(now, sizeof(now), t);
	fprintf(fp, "# %s public key\n# %s\n", __progname, now);
	if (comment)
		fprintf(fp, "# %s\n", comment);
	fprintf(fp, "Key: %s\n", hex);
	fclose(fp);
	free(hex);

	return 0;
}

static int
save_seckey(char *fname, unsigned char *k, size_t kz, char *comment,
    char *keyfile)
{
	FILE *fp;
	char *hex;
	char now[MAX_STRING];
	char passwd[MAX_PASSWD];
	size_t ctlen;
	size_t hexsize;
	time_t t;
	unsigned char *ct;
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES];

	/* Open secret key file. */
	if ((fp = fopen(fname, "w")) == NULL)
		err(1, "%s", fname);

	/* Allocate ciphertext. */
	ctlen = kz + crypto_secretbox_MACBYTES;
	if ((ct = sodium_malloc(ctlen)) == NULL)
		err(1, NULL);

	/* Random nonce and salt. */ 
	randombytes_buf(nonce, sizeof(nonce));
	randombytes_buf(salt, sizeof(salt));

	/* Read in passphrase. */
	if (keyfile)
		read_keyfile(keyfile, passwd, sizeof(passwd));
	else
		read_key(passwd, sizeof(passwd));

	/* Generate key from passphrase. */
	if (crypto_pwhash(key, sizeof(key), passwd, strlen(passwd), salt,
	    opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Clear passphrase from memory. */
	sodium_memzero(passwd, sizeof(passwd));

	/* Encrypt secret key. */
	crypto_secretbox_easy(ct, k, kz, nonce, key);
	sodium_memzero(key, sizeof(key));

	/* Write our secret key file. */
	time(&t);
	str_time(now, sizeof(now), t);
	fprintf(fp, "# %s secret key\n# %s\n", __progname, now);

	if (comment)
		fprintf(fp, "# %s\n", comment);

	fprintf(fp, "Opslimit: %llu\n", opslimit);
	fprintf(fp, "Memlimit: %ld\n", memlimit);

	/* Salt. */
	hexsize = sizeof(salt) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, salt, sizeof(salt));
	fprintf(fp, "Salt: %s\n", hex);
	free(hex);

	/* Nonce. */
	hexsize = sizeof(nonce) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, nonce, sizeof(nonce));
	fprintf(fp, "Nonce: %s\n", hex);
	free(hex);

	/* Ciphertext. */
	hexsize = ctlen * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, ct, ctlen);
	fprintf(fp, "Encrypted Key: %s\n", hex);
	free(hex);

	sodium_free(ct);
	fclose(fp);

	return 0;
}

static int
generate_key_pair(char *pub, char *sec, char *key, char *comment)
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];

	crypto_box_keypair(pk, sk);

	save_pubkey(pub, pk, sizeof(pk), comment);

	save_seckey(sec, sk, sizeof(sk), comment, key);
	explicit_bzero(sk, sizeof(sk));

	return 0;
}

static int
secret_key(char *infile, char *outfile, int enc)
{
	struct cipher_info *ci;
	unsigned char salt[crypto_pwhash_SALTBYTES];

	if ((ci = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);
	ci->enc = enc;

	/* Open input file. */
	if ((ci->fin = fopen(infile, "r")) == NULL)
		err(1, "%s", infile);

	/* Get the salt. */
	if (enc)
		randombytes_buf(salt, sizeof(salt));
	else {
		if (fread(salt, sizeof(salt), 1, ci->fin) != 1)
			errx(1, "error reading salt from %s", infile);
	}

	if (verbose)
		printf("opslimit = %lld, memlimit = %ld\n", opslimit, memlimit);

	/* Get the key from passphrase. */
	kdf(salt, 1, enc ? 1 : 0, ci->key);

	if (verbose) {
		print_value("salt", salt, sizeof(salt));
		print_value("key", ci->key, sizeof(ci->key));
	}

	/* Open output file. */
	if ((ci->fout = fopen(outfile, "w")) == NULL)
		err(1, "%s", outfile);

	if (enc) {
		/* Write salt to output file. */
		if (fwrite(salt, sizeof(salt), 1, ci->fout) != 1)
			errx(1, "error writing salt to %s", infile);
	}

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	/* Perform the crypto operation. */
	cipher(ci);

	/* Close files, zero and free memory. */
	fclose(ci->fin);
	fclose(ci->fout);
	sodium_memzero(ci, sizeof(struct cipher_info));
	free(ci);

	return 0;
}

static int
cipher(struct cipher_info *ci)
{
	size_t bufsize;
	size_t bytes;
	size_t rlen;
	size_t wlen;
	unsigned char *buf;
	unsigned char n[crypto_secretbox_NONCEBYTES];

	bufsize = BUFSIZE;
	if ((buf = malloc(bufsize)) == NULL)
		err(1, NULL);

	/*
	 * Determine how much we want to read based on operation.
	 * We need to reserve space for the MAC.
	 */
	rlen = ci->enc ? bufsize - crypto_secretbox_MACBYTES : bufsize;

	sodium_memzero(n, sizeof(n));
	while ((bytes = fread(buf, 1, rlen, ci->fin)) != 0) {
		sodium_increment(n, sizeof(n));
		/*
		 * Memory may overlap for both encrypt and decrypt.
		 * Ciphertext writes extra bytes for the MAC.
		 * Plaintext only writes the original data.
		 */
		if (ci->enc) {
			crypto_secretbox_easy(buf, buf, bytes, n, ci->key);
			wlen = bytes + crypto_secretbox_MACBYTES;
		} else {
			if (crypto_secretbox_open_easy(
			    buf, buf, bytes, n, ci->key) != 0)
				errx(1, "invalid message data");
			wlen = bytes - crypto_secretbox_MACBYTES;
		}
		if (fwrite(buf, wlen, 1, ci->fout) == 0)
			errx(1, "error writing to output stream");
	}
	if (ferror(ci->fin))
		errx(1, "error reading from input stream");

	sodium_memzero(buf, bufsize);
	free(buf);

	return 0;
}

static void
kdf(uint8_t *salt, int allowstdin, int confirm, uint8_t *key)
{
	char pass[MAX_PASSWD];
	int rppflags = RPP_ECHO_OFF;

	if (allowstdin && !isatty(STDIN_FILENO))
		rppflags |= RPP_STDIN;
	if (!readpassphrase("passphrase: ", pass, sizeof(pass), rppflags))
		errx(1, "unable to read passphrase");
	if (strlen(pass) == 0)
		errx(1, "please provide a password");
	if (confirm && !(rppflags & RPP_STDIN)) {
		char pass2[MAX_PASSWD];
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), rppflags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		sodium_memzero(pass2, sizeof(pass2));
	}
	if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, pass, strlen(pass),
	    salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) == -1)
		errx(1, "crypto_pwhash error");
	sodium_memzero(pass, sizeof(pass));
}

static void
print_value(char *name, unsigned char *bin, int size)
{
	char hex[MAX_LINE];

	sodium_bin2hex(hex, sizeof(hex), bin, size);
	printf("%s = %s\n", name, hex);
	sodium_memzero(hex, sizeof(hex));
}

/*
 * Set the mode.
 * 1) Interactive 2) Moderate 3) Sensitive
 * This will set parameters for the key derivation function.
 * See libsodium crypto_pwhash documentation.
 */
static void
set_mode(int mode)
{
	switch (mode) {
	case 1:
		opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
		memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
		break;
	case 2:
		opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
		memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
		break;
	case 3:
		opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
		memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;
		break;
	default:
		errx(1, "undefined mode %d", mode);
		break;
	}
}

static int
read_keyfile(char *keyfile, char *passwd, size_t pwsize)
{
	FILE *fp;
	char *line;
	size_t linesize;
	ssize_t linelen;

	if ((fp = fopen(keyfile, "r")) == NULL)
		err(1, "%s", keyfile);
	linesize = MAX_LINE;
	if ((line = sodium_malloc(linesize)) == NULL)
		err(1, NULL);
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		line[strcspn(line, "\n")] = '\0';
		strlcpy(passwd, line, pwsize);
		sodium_memzero(line, linesize);
	}
	sodium_free(line);
	if (ferror(fp))
		err(1, "%s", keyfile);
	fclose(fp);

	return 0;
}

static int
read_key(char *passwd, size_t size)
{
	return 0;
}

static char *
str_time(char *s, size_t z, time_t t)
{
	struct tm tm;

	memset(s, 0, z);
	memset(&tm, 0, sizeof(tm));
	localtime_r(&t, &tm);
	strftime(s, z - 1, "%Y-%m-%dT%H:%M:%S%z", &tm);

	return s;
}
