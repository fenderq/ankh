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
#include <stdlib.h>
#include <string.h>
#include <readpassphrase.h>
#include <unistd.h>
#include <util.h>

#include <sodium.h>

#define BUFSIZE 1024 * 1024
#define MAX_LINE 4096
#define MAX_PASSWD 1024
#define VERSION "1.0.0"

struct cipher_info {
	FILE *fin;
	FILE *fout;
	int enc;
	unsigned char key[crypto_secretbox_KEYBYTES];
};

unsigned char ankh_id[] = {
	0x5b, 0x71, 0x4d, 0x81, 0x91, 0x81, 0x35, 0xb1,
	0xb2, 0xea, 0x96, 0xaa, 0x80, 0xc8, 0x92, 0x57
};
unsigned int ankh_id_len = 16;

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
static char	*str_hex(char *, int, void *, int);
static void	 set_mode(int);
static int	 verify_ankh_id(FILE *);

int
main(int argc, char *argv[])
{
	char ch;
	const char *ep;
	int dflag;
	int mode;

	dflag = 0;
	mode = 2;

	if (pledge("cpath rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");

	if (sodium_init() == -1)
		errx(1, "libsodium init failure");

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
	struct cipher_info *c;
	unsigned char salt[crypto_pwhash_SALTBYTES];

	if ((c = calloc(1, sizeof(struct cipher_info))) == NULL)
		err(1, NULL);
	c->enc = enc;

	if ((c->fin = fopen(infile, "r")) == NULL)
		err(1, "%s", infile);
	if ((c->fout = fopen(outfile, "w")) == NULL)
		err(1, "%s", outfile);

	if (c->enc) {
		if (fwrite(ankh_id, ankh_id_len, 1, c->fout) != 1)
			errx(1, "error writing ankh_id to %s", infile);
		if (fwrite(&opslimit, sizeof(opslimit), 1, c->fout) != 1)
			errx(1, "error writing opslimit to %s", infile);
		if (fwrite(&memlimit, sizeof(memlimit), 1, c->fout) != 1)
			errx(1, "error writing memlimit to %s", infile);
		randombytes_buf(salt, sizeof(salt));
		if (fwrite(salt, sizeof(salt), 1, c->fout) != 1)
			errx(1, "error writing salt to %s", infile);
	} else {
		verify_ankh_id(c->fin);
		if (fread(&opslimit, sizeof(opslimit), 1, c->fin) != 1)
			errx(1, "error reading opslimit from %s", infile);
		if (fread(&memlimit, sizeof(memlimit), 1, c->fin) != 1)
			errx(1, "error reading memlimit from %s", infile);
		if (fread(salt, sizeof(salt), 1, c->fin) != 1)
			errx(1, "error reading salt from %s", infile);
	}

	if (verbose)
		printf("opslimit = %lld, memlimit = %ld\n", opslimit, memlimit);

	kdf(salt, 1, c->enc ? 1 : 0, c->key);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if (verbose) {
		print_value("salt", salt, sizeof(salt));
		print_value("key", c->key, sizeof(c->key));
	}

	enc ? encrypt(c) : decrypt(c);

	fclose(c->fin);
	fclose(c->fout);
	explicit_bzero(c, sizeof(struct cipher_info));
	free(c);

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

	while (feof(ci->fin) == 0) {
		if (fread(n, sizeof(n), 1, ci->fin) == 0)
			errx(1, "error reading nonce");
		if (verbose)
			print_value("nonce", n, sizeof(n));
		if (fread(mac, sizeof(mac), 1, ci->fin) == 0)
			errx(1, "error reading mac");
		if ((r = fread(c, 1, clen, ci->fin)) == 0) {
			if (ferror(ci->fin))
				errx(1, "error reading from input stream");
			break;
		}
		if (crypto_secretbox_open_detached(m,
		    c, mac, r, n, ci->key) != 0)
			errx(1, "invalid message data");
		if (fwrite(m, r, 1, ci->fout) == 0)
			errx(1, "failure writing to output stream");
	}

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

	while ((r = fread(m, 1, mlen, ci->fin)) != 0) {
		randombytes_buf(n, sizeof(n));
		crypto_secretbox_detached(c, mac, m, r, n, ci->key);
		if (fwrite(n, sizeof(n), 1, ci->fout) == 0)
			errx(1, "error writing nonce");
		if (verbose)
			print_value("nonce", n, sizeof(n));
		if (fwrite(mac, sizeof(mac), 1, ci->fout) == 0)
			errx(1, "error writing mac");
		if (fwrite(c, r, 1, ci->fout) == 0)
			errx(1, "failure writing to output stream");
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
		explicit_bzero(pass2, sizeof(pass2));
	}
	if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, pass, strlen(pass),
	    salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) == -1)
		errx(1, "crypto_pwhash failure");
	explicit_bzero(pass, sizeof(pass));
}

static void
print_value(char *name, unsigned char *str, int size)
{
	char buf[MAX_LINE];

	str_hex(buf, sizeof(buf), str, size);
	printf("%s = %s\n", name, buf);
	explicit_bzero(buf, sizeof(buf));
}

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

static char *
str_hex(char *str, int size, void *data, int len)
{
	const int hexsize = 2;
	int i;
	unsigned char *p;

	memset(str, 0, size);
	p = data;
	for (i = 0; i < len; i++) {
		if (size <= hexsize) {
			warnx("string truncation");
			break;
		}
		snprintf(str, size, "%02X", p[i]);
		size -= hexsize;
		str += hexsize;
	}

	return str;
}

static int
verify_ankh_id(FILE *fp)
{
	int bufsize;
	unsigned char *buf;

	bufsize = ankh_id_len;
	if ((buf = malloc(bufsize)) == NULL)
		err(1, NULL);
	if (fread(buf, bufsize, 1, fp) == 0 ||
	    memcmp(buf, ankh_id, bufsize) != 0)
		errx(1, "invalid file");
	free(buf);

	return 0;
}
