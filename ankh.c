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

#include <sys/queue.h>

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
#define MIN_PASSWD 16
#define MAX_STRING 256
#define VERSION "2.0.0"

enum command {
	CMD_UNDEFINED,
	CMD_GENERATE_KEY_PAIR,
	CMD_HASH,
	CMD_PUBLIC_KEY,
	CMD_SEALED_BOX,
	CMD_SECRET_KEY,
	CMD_SIGNATURE,
	CMD_VERSION
};

SLIST_HEAD(nvplist, nvp);
struct nvp {
	char *name;
	char *value;
	SLIST_ENTRY(nvp) entries;
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
static int	 generate_key_pair(char *, char *, char *);
static int	 read_passwd_tty(char *, size_t, int);
static int	 read_passwd_file(char *, size_t, char *);
static int	 secret_key(char *, char *, int, char *);
static void	 print_value(char *, unsigned char *, int);
static void	 set_mode(int);
static char	*str_time(char *, size_t, time_t);
int		 nvp_add(char *, char *, struct nvplist *);
void		 nvp_free(struct nvplist *);
int		 nvp_find(const char *, struct nvplist *, struct nvp **);
static int	 load_seckey(char *, unsigned char *, char *);
static int	 save_seckey(char *, unsigned char *, size_t, char *);
static int	 save_pubkey(char *, unsigned char *, size_t);

int
main(int argc, char *argv[])
{
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

	while ((ch = getopt(argc, argv, "BGHKPSVdi:k:m:o:p:s:v")) != -1) {
		switch (ch) {
		case 'B':
			if (cmd != CMD_UNDEFINED)
				usage();
			cmd = CMD_SEALED_BOX;
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
	case CMD_GENERATE_KEY_PAIR:
		generate_key_pair(pubkey, seckey, keyfile);
		break;
	case CMD_HASH:
		break;
	case CMD_PUBLIC_KEY:
		break;
	case CMD_SEALED_BOX:
		break;
	case CMD_SECRET_KEY:
		secret_key(infile, outfile, dflag ? 0 : 1, keyfile);
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
		ankh G [generate key pair] -m -p -s
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
load_pubkey(char *fname, unsigned char *k, size_t kz)
{
	FILE *fp;
	char *line;
	const char *name;
	size_t linesize;
	ssize_t linelen;
	struct nvp *np;
	struct nvplist lines;

	SLIST_INIT(&lines);

	/* Open the file. */
	if ((fp = fopen(fname, "r")) == NULL)
		err(1, "%s", fname);

	/* Create a tmp line. */
	linesize = MAX_LINE;
	if ((line = malloc(linesize)) == NULL)
		err(1, NULL);

	/* Add each line to a name/value list. */
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (line[0] == '#')
			continue;
		line[strcspn(line, "\n")] = '\0';
		nvp_add(line, ": ", &lines);
	}
	if (ferror(fp))
		err(1, "%s", fname);

	/* Free tmp line and close file. */
	free(line);
	fclose(fp);

	/* Get name/value pairs. */
	name = "key";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	if (sodium_hex2bin(k, kz, np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	/* Free lines. */
	nvp_free(&lines);

	if (verbose) {
		printf("reading file %s ...\n", fname);
		print_value("key", k, kz);
	}

	return 0;
}

static int
save_pubkey(char *fname, unsigned char *k, size_t kz)
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
	fprintf(fp, "key: %s\n", hex);
	fclose(fp);
	free(hex);

	return 0;
}

static int
load_seckey(char *fname, unsigned char *sk, char *keyfile)
{
	FILE *fp;
	char *line;
	char passwd[MAX_PASSWD];
	const char *ep;
	const char *name;
	size_t ctlen;
	size_t linesize;
	ssize_t linelen;
	struct nvp *np;
	struct nvplist lines;
	unsigned char *ct;
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES];

	SLIST_INIT(&lines);

	/* Open the file. */
	if ((fp = fopen(fname, "r")) == NULL)
		err(1, "%s", fname);

	/* Create a tmp line. */
	linesize = MAX_LINE;
	if ((line = malloc(linesize)) == NULL)
		err(1, NULL);

	/* Add each line to a name/value list. */
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if (line[0] == '#')
			continue;
		line[strcspn(line, "\n")] = '\0';
		nvp_add(line, ": ", &lines);
	}
	if (ferror(fp))
		err(1, "%s", fname);

	/* Free tmp line and close file. */
	free(line);
	fclose(fp);

	/* Get name/value pairs. */
	name = "opslimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	opslimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "opslimit %s", ep);

	name = "memlimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	memlimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "memlimit %s", ep);

	name = "salt";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	if (sodium_hex2bin(salt, sizeof(salt), np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "nonce";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	if (sodium_hex2bin(nonce, sizeof(nonce), np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "key";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, fname);
	ctlen = strlen(np->value) / 2;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);
	if (sodium_hex2bin(ct, ctlen, np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	/* Free lines. */
	nvp_free(&lines);

	if (verbose) {
		printf("reading file %s ...\n", fname);
		printf("opslimit = %llu\n", opslimit);
		printf("memlimit = %ld\n", memlimit);
		print_value("salt", salt, sizeof(salt));
		print_value("nonce", nonce, sizeof(nonce));
		print_value("key", ct, ctlen);
	}

	/* Read in passphrase. */
	if (keyfile)
		read_passwd_file(passwd, sizeof(passwd), keyfile);
	else
		read_passwd_tty(passwd, sizeof(passwd), 1);

	/* Generate key from passphrase. */
	if (crypto_pwhash(key, sizeof(key), passwd, strlen(passwd), salt,
	    opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Clear passphrase from memory. */
	sodium_memzero(passwd, sizeof(passwd));

	/* Decrypt the secret key. */
	if (crypto_secretbox_open_easy(sk, ct, ctlen, nonce, key) != 0)
		errx(1, "invalid secret key");

	/* Clear key from memory. */
	sodium_memzero(key, sizeof(key));

	free(ct);

	return 0;
}

static int
save_seckey(char *fname, unsigned char *k, size_t kz, char *keyfile)
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
		read_passwd_file(passwd, sizeof(passwd), keyfile);
	else
		read_passwd_tty(passwd, sizeof(passwd), 1);

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

	fprintf(fp, "opslimit: %llu\n", opslimit);
	fprintf(fp, "memlimit: %ld\n", memlimit);

	/* Salt. */
	hexsize = sizeof(salt) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, salt, sizeof(salt));
	fprintf(fp, "salt: %s\n", hex);
	free(hex);

	/* Nonce. */
	hexsize = sizeof(nonce) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, nonce, sizeof(nonce));
	fprintf(fp, "nonce: %s\n", hex);
	free(hex);

	/* Ciphertext. */
	hexsize = ctlen * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, ct, ctlen);
	fprintf(fp, "key: %s\n", hex);
	free(hex);

	sodium_free(ct);
	fclose(fp);

	return 0;
}

static int
generate_key_pair(char *pub, char *sec, char *key)
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];

	crypto_box_keypair(pk, sk);

	save_seckey(sec, sk, sizeof(sk), key);
	save_pubkey(pub, pk, sizeof(pk));

	sodium_memzero(sk, sizeof(sk));

	load_seckey(sec, sk, key);
	load_pubkey(pub, pk, sizeof(pk));

	sodium_memzero(sk, sizeof(sk));

	return 0;
}

static int
secret_key(char *infile, char *outfile, int enc, char *keyfile)
{
	char passwd[MAX_PASSWD];
	struct cipher_info *ci;
	unsigned char salt[crypto_pwhash_SALTBYTES];

	if ((ci = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);
	ci->enc = enc;

	/* Open input. */
	if (infile == NULL)
		ci->fin = stdin;
	else if ((ci->fin = fopen(infile, "r")) == NULL)
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

	/* Read in passphrase. */
	if (keyfile)
		read_passwd_file(passwd, sizeof(passwd), keyfile);
	else
		read_passwd_tty(passwd, sizeof(passwd), enc ? 1 : 0);

	/* Generate key from passphrase. */
	if (crypto_pwhash(ci->key, sizeof(ci->key), passwd, strlen(passwd),
	    salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Clear passphrase from memory. */
	sodium_memzero(passwd, sizeof(passwd));

	if (verbose) {
		print_value("salt", salt, sizeof(salt));
		print_value("key", ci->key, sizeof(ci->key));
	}

	/* Open output. */
	if (outfile == NULL)
		ci->fout = stdout;
	else if ((ci->fout = fopen(outfile, "w")) == NULL)
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
	if (ci->fin != stdin)
		fclose(ci->fin);
	if (ci->fout != stdout)
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
read_passwd_file(char *pass, size_t size, char *fname)
{
	FILE *fp;
	char *line;
	int linecount;
	size_t linesize;
	ssize_t linelen;
	size_t passlen;

	if ((fp = fopen(fname, "r")) == NULL)
		err(1, "%s", fname);
	linesize = MAX_LINE;
	if ((line = sodium_malloc(linesize)) == NULL)
		err(1, NULL);
	linecount = 0;
	memset(pass, 0, size);
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		line[strcspn(line, "\n")] = '\0';
		strlcpy(pass, line, size);
		sodium_memzero(line, linesize);
		linecount++;
	}
	if (linecount > 1)
		errx(1, "%s contains multiple lines (%d)", fname, linecount);
	passlen = strlen(pass);
	if (passlen == 0)
		errx(1, "please provide a password");
	if (passlen < MIN_PASSWD)
		errx(1, "password too small");
	sodium_free(line);
	if (ferror(fp))
		err(1, "%s", fname);
	fclose(fp);

	return 0;
}

static int
read_passwd_tty(char *pass, size_t size, int confirm)
{
	char pass2[MAX_PASSWD];
	int flags;
	size_t passlen;

	flags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;

	if (!readpassphrase("passphrase: ", pass, size, flags))
		errx(1, "unable to read passphrase");
	passlen = strlen(pass);
	if (passlen == 0)
		errx(1, "please provide a password");
	if (confirm) {
		if (passlen < MIN_PASSWD)
			errx(1, "password too small");
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), flags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		sodium_memzero(pass2, sizeof(pass2));
	}

	return 0;
}

static char *
str_time(char *str, size_t size, time_t t)
{
	struct tm tm;

	memset(str, 0, size);
	memset(&tm, 0, sizeof(tm));
	localtime_r(&t, &tm);
	strftime(str, size - 1, "%Y-%m-%dT%H:%M:%S%z", &tm);

	return str;
}

int
nvp_add(char *line, char *delimiter, struct nvplist *head)
{
	char *p;
	size_t len;
	struct nvp *np;

	if ((p = strstr(line, delimiter)) == NULL)
		errx(1, "invalid line %s", line);
	if ((np = malloc(sizeof(struct nvp))) == NULL)
		err(1, NULL);
	len = p - line;
	p += strlen(delimiter);
	np->name = strndup(line, len);
	np->value = strdup(p);
	SLIST_INSERT_HEAD(head, np, entries);

	return 0;
}

void
nvp_free(struct nvplist *head)
{
	struct nvp *np;

	while (!SLIST_EMPTY(head)) {
		np = SLIST_FIRST(head);
		SLIST_REMOVE_HEAD(head, entries);
		free(np->name);
		free(np->value);
		free(np);
	}
}

int
nvp_find(const char *name, struct nvplist *head, struct nvp **item)
{
	struct nvp *np;

	SLIST_FOREACH(np, head, entries) {
		if (strcmp(np->name, name) == 0) {
			*item = np;
			return 0;
		}
	}

	return 1;
}
