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
#define MAGIC_LEN 16
#define MAX_LINE 4096
#define PASSWD_MAX 128
#define PASSWD_MIN 8
#define STRING_MAX 256

#define MAJ 2
#define MIN 0
#define REV 1

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

struct ankh_header {
	unsigned char id[MAGIC_LEN];
	int maj;
	int min;
	int rev;
	enum command cmd;
};

struct ankh {
	FILE *fin;
	FILE *fout;
	char infile[PATH_MAX];
	char keyfile[PATH_MAX];
	char outfile[PATH_MAX];
	char passwd[PASSWD_MAX];
	char pubfile[PATH_MAX];
	char secfile[PATH_MAX];
	enum command cmd;
	int enc;
	size_t memlimit;
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES];
	unsigned char seckey[crypto_box_SECRETKEYBYTES];
	unsigned long long opslimit;
};

SLIST_HEAD(nvplist, nvp);
struct nvp {
	char *name;
	char *value;
	SLIST_ENTRY(nvp) entries;
};

extern char *optarg;

int verbose;
struct ankh *clrptr;

unsigned char magic[] = {
	0x9f, 0x29, 0x50, 0x63, 0xc0, 0x86, 0xa4, 0x0f,
	0x9c, 0x88, 0x22, 0x92, 0xdc, 0x99, 0x8b, 0xe4
};

__dead void usage(void);

int	 cipher(struct ankh *);
int	 do_command(struct ankh *);
int	 generate_key_pair(struct ankh *);
int	 hdr_read(struct ankh *, struct ankh_header *);
int	 hdr_write(struct ankh *, struct ankh_header *);
int	 load_pubkey(struct ankh *);
int	 load_seckey(struct ankh *);
int	 nvp_add(char *, char *, struct nvplist *);
int	 nvp_find(const char *, struct nvplist *, struct nvp **);
void	 nvp_free(struct nvplist *);
void	 print_value(char *, unsigned char *, int);
int	 read_passwd_file(char *, size_t, char *);
int	 read_passwd_tty(char *, size_t, int);
int	 save_pubkey(struct ankh *);
int	 save_seckey(struct ankh *);
int	 sealed_box(struct ankh *);
int	 secret_key(struct ankh *);
void	 set_mode(struct ankh *, int);
char	*str_time(char *, size_t, time_t);

int
main(int argc, char *argv[])
{
	char ch;
	const char *ep;
	int mode;
	struct ankh a;

	if (pledge("cpath rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");

	mode = DEFAULT_MODE;

	memset(&a, 0, sizeof(a));
	a.cmd = CMD_UNDEFINED;
	a.enc = 1;

	if (sodium_init() == -1)
		errx(1, "libsodium init error");

	while ((ch = getopt(argc, argv, "BGHKPSVdi:k:m:o:p:s:v")) != -1) {
		switch (ch) {
		case 'B':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_SEALED_BOX;
			break;
		case 'G':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_GENERATE_KEY_PAIR;
			break;
		case 'H':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_HASH;
			break;
		case 'K':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_SECRET_KEY;
			break;
		case 'P':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_PUBLIC_KEY;
			break;
		case 'S':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_SIGNATURE;
			break;
		case 'V':
			if (a.cmd != CMD_UNDEFINED)
				usage();
			a.cmd = CMD_VERSION;
			break;
		case 'd':
			a.enc = 0;
			break;
		case 'i':
			strlcpy(a.infile, optarg, sizeof(a.infile));
			break;
		case 'k':
			strlcpy(a.keyfile, optarg, sizeof(a.keyfile));
			break;
		case 'm':
			mode = strtonum(optarg, 1, 3, &ep);
			if (ep != NULL)
				errx(1, "mode %s", ep);
			break;
		case 'p':
			strlcpy(a.pubfile, optarg, sizeof(a.pubfile));
			break;
		case 'o':
			strlcpy(a.outfile, optarg, sizeof(a.outfile));
			break;
		case 's':
			strlcpy(a.secfile, optarg, sizeof(a.secfile));
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

	set_mode(&a, mode);
	do_command(&a);

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	/*
		ankh K (secret key) [-dikmo]
		ankh G (generate key pair) [-km] -p -s
		ankh B (sealed box) [-diko] -p -s
		ankh P (public key) [-diko] -p -s
		ankh S (signature) [-iko] -p -s
		ankh H (hash) [-io]
		ankh V (version)
	 */
	fprintf(stderr, "usage:"
	    "\t%1$s -K [-dikmo]\n"
	    "\t%1$s -G [-km] -s seckey -p pubkey\n"
	    "\t%1$s -B [-diko] -s seckey -p pubkey\n"
	    "\t%1$s -V\n",
	    getprogname());

	exit(EXIT_FAILURE);
}

int
cipher(struct ankh *a)
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
	rlen = a->enc ? bufsize - crypto_secretbox_MACBYTES : bufsize;

	memset(n, 0, sizeof(n));
	while ((bytes = fread(buf, 1, rlen, a->fin)) != 0) {
		sodium_increment(n, sizeof(n));
		/*
		 * Memory may overlap for both encrypt and decrypt.
		 * Ciphertext writes extra bytes for the MAC.
		 * Plaintext only writes the original data.
		 */
		if (a->enc) {
			crypto_secretbox_easy(buf, buf, bytes, n, a->key);
			wlen = bytes + crypto_secretbox_MACBYTES;
		} else {
			if (crypto_secretbox_open_easy(
			    buf, buf, bytes, n, a->key) != 0)
				errx(1, "invalid message data");
			wlen = bytes - crypto_secretbox_MACBYTES;
		}
		if (fwrite(buf, wlen, 1, a->fout) == 0)
			errx(1, "error writing to output stream");
	}
	if (ferror(a->fin))
		errx(1, "error reading from input stream");

	explicit_bzero(buf, bufsize);
	free(buf);

	return 0;
}

int
do_command(struct ankh *a)
{
	switch (a->cmd) {
	case CMD_UNDEFINED:
		usage();
		break;
	case CMD_GENERATE_KEY_PAIR:
		generate_key_pair(a);
		break;
	case CMD_HASH:
		break;
	case CMD_PUBLIC_KEY:
		break;
	case CMD_SEALED_BOX:
		sealed_box(a);
		break;
	case CMD_SECRET_KEY:
		secret_key(a);
		break;
	case CMD_SIGNATURE:
		break;
	case CMD_VERSION:
		printf("%s %d.%d.%d (libsodium %s)\n", getprogname(),
		    MAJ, MIN, REV, sodium_version_string());
		break;
	}

	return 0;
}

int
generate_key_pair(struct ankh *a)
{
	crypto_box_keypair(a->pubkey, a->seckey);

	save_seckey(a);
	save_pubkey(a);
	explicit_bzero(a->seckey, sizeof(a->seckey));

	return 0;
}

int
hdr_read(struct ankh *a, struct ankh_header *h)
{
	/* Read the header. */
	if (fread(h, sizeof(struct ankh_header), 1, a->fin) != 1)
		errx(1, "failure to read header");

	/* Verify this is an ankh file. */
	if (memcmp(h->id, magic, sizeof(h->id)) != 0)
		errx(1, "invalid %s file", getprogname());

	/* Verify file type matches command. */
	if (h->cmd != a->cmd)
		errx(1, "invalid file type %d for command %d", h->cmd, a->cmd);

	return 0;
}

int
hdr_write(struct ankh *a, struct ankh_header *h)
{
	memset(h, 0, sizeof(struct ankh_header));

	memcpy(h->id, magic, sizeof(h->id));
	h->maj = MAJ;
	h->min = MIN;
	h->rev = REV;
	h->cmd = a->cmd;

	if (fwrite(h, sizeof(struct ankh_header), 1, a->fout) != 1)
		errx(1, "failure to write header");

	return 0;
}

int
load_pubkey(struct ankh *a)
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
	if ((fp = fopen(a->pubfile, "r")) == NULL)
		err(1, "%s", a->pubfile);

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
		err(1, "%s", a->pubfile);

	/* Free tmp line and close file. */
	free(line);
	fclose(fp);

	/* Get name/value pairs. */
	name = "key";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->pubfile);
	if (sodium_hex2bin(a->pubkey, sizeof(a->pubkey), np->value,
	    strlen(np->value), NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	/* Free lines. */
	nvp_free(&lines);

	return 0;
}

int
load_seckey(struct ankh *a)
{
	FILE *fp;
	char *line;
	const char *ep;
	const char *name;
	size_t ctlen;
	size_t linesize;
	ssize_t linelen;
	struct nvp *np;
	struct nvplist lines;
	unsigned char *ct;

	SLIST_INIT(&lines);

	/* Open the file. */
	if ((fp = fopen(a->secfile, "r")) == NULL)
		err(1, "%s", a->secfile);

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
		err(1, "%s", a->secfile);

	/* Free tmp line and close file. */
	free(line);
	fclose(fp);

	/* Get name/value pairs. */
	name = "opslimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	a->opslimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "opslimit %s", ep);

	name = "memlimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	a->memlimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "memlimit %s", ep);

	name = "salt";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	if (sodium_hex2bin(a->salt, sizeof(a->salt), np->value,
	    strlen(np->value), NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "nonce";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	if (sodium_hex2bin(a->nonce, sizeof(a->nonce), np->value,
	    strlen(np->value), NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "key";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	ctlen = strlen(np->value) / 2;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);
	if (sodium_hex2bin(ct, ctlen, np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	/* Free lines. */
	nvp_free(&lines);

	/* Read in passphrase. */
	if (a->keyfile[0] != '\0')
		read_passwd_file(a->passwd, sizeof(a->passwd), a->keyfile);
	else
		read_passwd_tty(a->passwd, sizeof(a->passwd), 0);

	/* Generate key from passphrase. */
	if (crypto_pwhash(a->key, sizeof(a->key), a->passwd, strlen(a->passwd),
	    a->salt, a->opslimit, a->memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Clear passphrase from memory. */
	explicit_bzero(a->passwd, sizeof(a->passwd));

	/* Decrypt the secret key. */
	if (crypto_secretbox_open_easy(a->seckey, ct, ctlen, a->nonce,
	    a->key) != 0)
		errx(1, "invalid secret key");

	/* Clear key from memory. */
	explicit_bzero(a->key, sizeof(a->key));

	free(ct);

	return 0;
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

void
print_value(char *name, unsigned char *bin, int size)
{
	char hex[MAX_LINE];

	sodium_bin2hex(hex, sizeof(hex), bin, size);
	printf("%s = %s\n", name, hex);
	explicit_bzero(hex, sizeof(hex));
}

int
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
	if ((line = malloc(linesize)) == NULL)
		err(1, NULL);
	linecount = 0;
	memset(pass, 0, size);
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		line[strcspn(line, "\n")] = '\0';
		strlcpy(pass, line, size);
		explicit_bzero(line, linesize);
		linecount++;
	}
	if (linecount > 1)
		errx(1, "%s contains multiple lines (%d)", fname, linecount);
	passlen = strlen(pass);
	if (passlen == 0)
		errx(1, "please provide a password");
	if (passlen < PASSWD_MIN)
		errx(1, "password too small");
	free(line);
	if (ferror(fp))
		err(1, "%s", fname);
	fclose(fp);

	return 0;
}

int
read_passwd_tty(char *pass, size_t size, int confirm)
{
	char pass2[PASSWD_MAX];
	int flags;
	size_t passlen;

	flags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;

	if (!readpassphrase("passphrase: ", pass, size, flags))
		errx(1, "unable to read passphrase");
	passlen = strlen(pass);
	if (passlen == 0)
		errx(1, "please provide a password");
	if (confirm) {
		if (passlen < PASSWD_MIN)
			errx(1, "password too small");
		if (!readpassphrase("confirm passphrase: ", pass2,
		    sizeof(pass2), flags))
			errx(1, "unable to read passphrase");
		if (strcmp(pass, pass2) != 0)
			errx(1, "passwords don't match");
		explicit_bzero(pass2, sizeof(pass2));
	}

	return 0;
}

int
save_pubkey(struct ankh *a)
{
	FILE *fp;
	char *hex;
	char now[STRING_MAX];
	size_t hexsize;
	time_t t;

	hexsize = sizeof(a->pubkey) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, a->pubkey, sizeof(a->pubkey));
	if ((fp = fopen(a->pubfile, "w")) == NULL)
		err(1, "%s", a->pubfile);
	time(&t);
	str_time(now, sizeof(now), t);
	fprintf(fp, "# %s public key\n# %s\n", getprogname(), now);
	fprintf(fp, "key: %s\n", hex);
	fclose(fp);
	free(hex);

	return 0;
}

int
save_seckey(struct ankh *a)
{
	FILE *fp;
	char *hex;
	char now[STRING_MAX];
	size_t ctlen;
	size_t hexsize;
	time_t t;
	unsigned char *ct;

	/* Open secret key file. */
	if ((fp = fopen(a->secfile, "w")) == NULL)
		err(1, "%s", a->secfile);

	/* Allocate ciphertext. */
	ctlen = sizeof(a->seckey) + crypto_secretbox_MACBYTES;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);

	/* Random nonce and salt. */
	arc4random_buf(a->nonce, sizeof(a->nonce));
	arc4random_buf(a->salt, sizeof(a->salt));

	/* Read in passphrase. */
	if (a->keyfile[0] != '\0')
		read_passwd_file(a->passwd, sizeof(a->passwd), a->keyfile);
	else
		read_passwd_tty(a->passwd, sizeof(a->passwd), 1);

	/* Generate key from passphrase. */
	if (crypto_pwhash(a->key, sizeof(a->key), a->passwd, strlen(a->passwd),
	    a->salt, a->opslimit, a->memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Clear passphrase from memory. */
	explicit_bzero(a->passwd, sizeof(a->passwd));

	/* Encrypt secret key. */
	crypto_secretbox_easy(ct, a->seckey, sizeof(a->seckey),
	    a->nonce, a->key);
	explicit_bzero(a->key, sizeof(a->key));

	/* Write our secret key file. */
	time(&t);
	str_time(now, sizeof(now), t);
	fprintf(fp, "# %s secret key\n# %s\n", getprogname(), now);

	fprintf(fp, "opslimit: %llu\n", a->opslimit);
	fprintf(fp, "memlimit: %ld\n", a->memlimit);

	/* Salt. */
	hexsize = sizeof(a->salt) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, a->salt, sizeof(a->salt));
	fprintf(fp, "salt: %s\n", hex);
	free(hex);

	/* Nonce. */
	hexsize = sizeof(a->nonce) * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, a->nonce, sizeof(a->nonce));
	fprintf(fp, "nonce: %s\n", hex);
	free(hex);

	/* Ciphertext. */
	hexsize = ctlen * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, ct, ctlen);
	fprintf(fp, "key: %s\n", hex);
	free(hex);

	free(ct);
	fclose(fp);

	return 0;
}

/*
 * Sealed Box ie. Ransomware
 */
int
sealed_box(struct ankh *a)
{
	struct ankh_header hdr;
	size_t ctlen;
	unsigned char *ct;

	memset(&hdr, 0, sizeof(hdr));

	/* Open input. */
	if (a->infile[0] == '\0')
		a->fin = stdin;
	else if ((a->fin = fopen(a->infile, "r")) == NULL)
			err(1, "%s", a->infile);

	/* Open output. */
	if (a->outfile[0] == '\0')
		a->fout = stdout;
	else if ((a->fout = fopen(a->outfile, "w")) == NULL)
		err(1, "%s", a->outfile);

	ctlen = sizeof(a->key) + crypto_box_SEALBYTES;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);

	if (a->enc) {
		hdr_write(a, &hdr);

		load_pubkey(a);

		arc4random_buf(a->key, sizeof(a->key));
		crypto_box_seal(ct, a->key, sizeof(a->key), a->pubkey);
		fwrite(ct, ctlen, 1, a->fout);

		arc4random_buf(a->salt, sizeof(a->salt));
		fwrite(a->salt, sizeof(a->salt), 1, a->fout);
	} else {
		hdr_read(a, &hdr);

		fread(ct, ctlen, 1, a->fin);
		fread(a->salt, sizeof(a->salt), 1, a->fin);

		load_pubkey(a);
		load_seckey(a);

		if (crypto_box_seal_open(a->key, ct, ctlen,
		    a->pubkey, a->seckey) != 0)
			errx(1, "crypto_box_seal_open error");

		explicit_bzero(a->seckey, sizeof(a->seckey));
	}

	free(ct);

	cipher(a);

	explicit_bzero(a->key, sizeof(a->key));

	/* Close files and zero memory. */
	if (a->fin != stdin)
		fclose(a->fin);
	if (a->fout != stdout)
		fclose(a->fout);

	return 0;
}

int
secret_key(struct ankh *a)
{
	struct ankh_header hdr;

	/* Open input. */
	if (a->infile[0] == '\0')
		a->fin = stdin;
	else if ((a->fin = fopen(a->infile, "r")) == NULL)
			err(1, "%s", a->infile);

	/* Get the salt. */
	if (a->enc)
		arc4random_buf(a->salt, sizeof(a->salt));
	else {
		hdr_read(a, &hdr);
		if (fread(&a->opslimit, sizeof(a->opslimit), 1, a->fin) != 1)
			errx(1, "error reading opslimit");
		if (fread(&a->memlimit, sizeof(a->memlimit), 1, a->fin) != 1)
			errx(1, "error reading memlimit");
		if (fread(a->salt, sizeof(a->salt), 1, a->fin) != 1)
			errx(1, "error reading salt");
	}

	if (verbose) {
		printf("opslimit = %lld, memlimit = %ld\n", a->opslimit,
		    a->memlimit);
	}

	/* Read passphrase. */
	if (a->keyfile[0] != '\0')
		read_passwd_file(a->passwd, sizeof(a->passwd), a->keyfile);
	else
		read_passwd_tty(a->passwd, sizeof(a->passwd), a->enc ? 1 : 0);

	/* Generate key from passphrase. */
	if (crypto_pwhash(a->key, sizeof(a->key), a->passwd, strlen(a->passwd),
	    a->salt, a->opslimit, a->memlimit, crypto_pwhash_ALG_DEFAULT) != 0)
		errx(1, "libsodium crypto_pwhash: out of memory");

	/* Zero passphrase in memory. */
	explicit_bzero(a->passwd, sizeof(a->passwd));

	if (verbose) {
		print_value("salt", a->salt, sizeof(a->salt));
		print_value("key", a->key, sizeof(a->key));
	}

	/* Open output. */
	if (a->outfile[0] == '\0')
		a->fout = stdout;
	else if ((a->fout = fopen(a->outfile, "w")) == NULL)
		err(1, "%s", a->outfile);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	/* Write header info. */
	if (a->enc) {
		hdr_write(a, &hdr);
		if (fwrite(&a->opslimit, sizeof(a->opslimit), 1, a->fout) != 1)
			errx(1, "error writing opslimit");
		if (fwrite(&a->memlimit, sizeof(a->memlimit), 1, a->fout) != 1)
			errx(1, "error writing memlimit");
		if (fwrite(a->salt, sizeof(a->salt), 1, a->fout) != 1)
			errx(1, "error writing salt");
	}

	/* Perform the crypto operation. */
	cipher(a);

	explicit_bzero(a->key, sizeof(a->key));

	/* Close files and zero memory. */
	if (a->fin != stdin)
		fclose(a->fin);
	if (a->fout != stdout)
		fclose(a->fout);

	return 0;
}

/*
 * Set the mode.
 * 1) Interactive 2) Moderate 3) Sensitive
 * This will set parameters for the key derivation function.
 * See libsodium crypto_pwhash documentation.
 */
void
set_mode(struct ankh *a, int mode)
{
	switch (mode) {
	case 1:
		a->opslimit = crypto_pwhash_OPSLIMIT_INTERACTIVE;
		a->memlimit = crypto_pwhash_MEMLIMIT_INTERACTIVE;
		break;
	case 2:
		a->opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
		a->memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
		break;
	case 3:
		a->opslimit = crypto_pwhash_OPSLIMIT_SENSITIVE;
		a->memlimit = crypto_pwhash_MEMLIMIT_SENSITIVE;
		break;
	default:
		errx(1, "undefined mode %d", mode);
		break;
	}
}

char *
str_time(char *str, size_t size, time_t t)
{
	struct tm tm;

	memset(str, 0, size);
	memset(&tm, 0, sizeof(tm));
	localtime_r(&t, &tm);
	strftime(str, size - 1, "%Y-%m-%dT%H:%M:%S%z", &tm);

	return str;
}
