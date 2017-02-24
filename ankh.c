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
#include <readpassphrase.h>
#include <unistd.h>

#include <sodium.h>

#define BUFSIZE 1024 * 1024
#define DEFAULT_MODE 3
#define MAX_LINE 4096
#define MAX_PASSWD 1024
#define VERSION "1.1.0"

struct cipher_info {
	FILE *fin;
	FILE *fout;
	unsigned char key[crypto_secretbox_KEYBYTES];
};

extern char *__progname;
extern char *optarg;

size_t memlimit;
unsigned long long opslimit;
int verbose;

__dead void usage(void);

static int	 ankh(char *, char *, int);
static int	 decrypt(struct cipher_info *);
static int	 encrypt(struct cipher_info *);
static void	 kdf(uint8_t *, int, int, uint8_t *);
static void	 print_value(char *, unsigned char *, int);
static void	 set_mode(int);

int
main(int argc, char *argv[])
{
	char ch;
	const char *ep;
	int dflag;
	int mode;

	dflag = 0;
	mode = DEFAULT_MODE;

	if (pledge("cpath rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");

	if (sodium_init() == -1)
		errx(1, "libsodium init error");

	while ((ch = getopt(argc, argv, "dm:v")) != -1) {
		switch (ch) {
		case 'd':
			dflag = 1;
			break;
		case 'm':
			mode = strtonum(optarg, 1, 3, &ep);
			if (ep != NULL)
				errx(1, "mode %s", ep);
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

	if (argc != 2)
		usage();

	set_mode(mode);

	ankh(argv[0], argv[1], dflag ? 0 : 1);

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-dmv] infile outfile\n", __progname);
	exit(EXIT_FAILURE);
}

static int
ankh(char *infile, char *outfile, int enc)
{
	struct cipher_info *ci;
	unsigned char salt[crypto_pwhash_SALTBYTES];

	if ((ci = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);

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
	enc ? encrypt(ci) : decrypt(ci);

	/* Close files, zero and free memory. */
	fclose(ci->fin);
	fclose(ci->fout);
	sodium_memzero(ci, sizeof(struct cipher_info));
	free(ci);

	return 0;
}

static int
decrypt(struct cipher_info *ci)
{
	int clen;
	int mlen;
	size_t r;
	unsigned char *c;
	unsigned char *m;
	unsigned char mac[crypto_secretbox_MACBYTES];
	unsigned char n[crypto_secretbox_NONCEBYTES];

	clen = BUFSIZE;
	if ((c = malloc(clen)) == NULL)
		err(1, NULL);
	mlen = BUFSIZE;
	if ((m = malloc(mlen)) == NULL)
		err(1, NULL);

	sodium_memzero(n, sizeof(n));
	do {
		sodium_increment(n, sizeof(n));
		if (fread(mac, sizeof(mac), 1, ci->fin) == 0) {
			if (ferror(ci->fin))
				errx(1, "error reading mac");
			break;
		}
		if (verbose) {
			print_value("nonce", n, sizeof(n));
			print_value("mac", mac, sizeof(mac));
		}
		if ((r = fread(c, 1, clen, ci->fin)) == 0) {
			if (ferror(ci->fin))
				errx(1, "error reading from input stream");
			else
				warnx("mac without ciphertext");
			break;
		}
		if (crypto_secretbox_open_detached(
		    m, c, mac, r, n, ci->key) != 0)
			errx(1, "invalid message data");
		if (fwrite(m, r, 1, ci->fout) == 0)
			errx(1, "error writing to output stream");
	} while (1);

	free(c);
	free(m);

	return 0;
}

static int
encrypt(struct cipher_info *ci)
{
	int clen;
	int mlen;
	size_t r;
	unsigned char *c;
	unsigned char *m;
	unsigned char mac[crypto_secretbox_MACBYTES];
	unsigned char n[crypto_secretbox_NONCEBYTES];

	clen = BUFSIZE;
	if ((c = malloc(clen)) == NULL)
		err(1, NULL);
	mlen = BUFSIZE;
	if ((m = malloc(mlen)) == NULL)
		err(1, NULL);

	sodium_memzero(n, sizeof(n));
	while ((r = fread(m, 1, mlen, ci->fin)) != 0) {
		sodium_increment(n, sizeof(n));
		crypto_secretbox_detached(c, mac, m, r, n, ci->key);
		if (verbose) {
			print_value("nonce", n, sizeof(n));
			print_value("mac", mac, sizeof(mac));
		}
		if (fwrite(mac, sizeof(mac), 1, ci->fout) == 0)
			errx(1, "error writing mac");
		if (fwrite(c, r, 1, ci->fout) == 0)
			errx(1, "error writing to output stream");
	}
	if (ferror(ci->fin))
		errx(1, "error reading from input stream");

	free(c);
	free(m);

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
