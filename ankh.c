/*
 * Copyright (c) 2017, 2018 Steven Roberts <sroberts@fenderq.com>
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
#include <sys/stat.h>
#include <sys/types.h>

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <readpassphrase.h>

#include <sodium.h>

#define BUFSIZE (1024 * 1024)
#define DEFAULT_MODE 2
#define HEADER_PARAM_SIZE 64
#define MAGIC_LEN 16
#define MAX_LINE 4096
#define PASSWD_MAX 128
#define PASSWD_MIN 8
#define STRING_MAX 256

#define MAJ 3
#define MIN 0
#define REV 0

enum command {
	CMD_UNDEFINED,
	CMD_GENERATE_KEY_PAIR,
	CMD_PUBLIC_KEY,
	CMD_SEALED_BOX,
	CMD_SECRET_KEY,
	CMD_VERSION
};

struct ankh {
	FILE *fin;
	FILE *fout;
	char algoname[STRING_MAX];
	char keyfile[PATH_MAX];
	char pubfile[PATH_MAX];
	char secfile[PATH_MAX];
	enum command cmd;
	int (*cipher_func)(struct ankh *);
	int algo;
	int enc;
	int mode;
	size_t memlimit;
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	unsigned char pubkey[crypto_box_PUBLICKEYBYTES];
	unsigned char seckey[crypto_box_SECRETKEYBYTES];
	unsigned long long opslimit;
};

struct kdfinfo {
	const char *name;
	int algo;
} kdflist[] = {
	{ "argon2i", crypto_pwhash_ALG_ARGON2I13 },
	{ "argon2id", crypto_pwhash_ALG_ARGON2ID13 }
};

SLIST_HEAD(nvplist, nvp);
struct nvp {
	char *name;
	char *value;
	SLIST_ENTRY(nvp) entries;
};

extern char *optarg;

int verbose;
struct ankh *adp;

unsigned char v2[] = {
	0x7e, 0x82, 0x72, 0x2d, 0xfc, 0xac, 0xf3, 0x05,
	0x99, 0x7f, 0xee, 0x77, 0x34, 0x15, 0x7f, 0x5a
};

unsigned char magic[] = {
	0xa4, 0xfb, 0x24, 0x78, 0xc1, 0x08, 0x26, 0x10,
	0x7e, 0x5c, 0xa3, 0x39, 0x9f, 0x36, 0x36, 0x99
};

__dead void usage(void);

void		 cleanup(void);
int		 data_write(FILE *, char *, void *, size_t);
int	 	 do_command(struct ankh *);
int	 	 generate_key_pair(struct ankh *);
char		*getid(char *, size_t);
int	 	 header_read(struct ankh *);
int	 	 header_write(struct ankh *);
int		 kdf(unsigned char *, char *, unsigned char *, int,
		     unsigned long long, size_t, int);
int	 	 nvp_add(char *, char *, struct nvplist *);
int	 	 nvp_find(const char *, struct nvplist *, struct nvp **);
void	 	 nvp_free(struct nvplist *);
int	 	 passwd_read_file(char *, size_t, char *);
int	 	 passwd_read_tty(char *, size_t, int);
void	 	 print_value(char *, unsigned char *, int);
int	 	 pubkey_read(struct ankh *);
int	 	 pubkey_write(struct ankh *);
int		 public_key(struct ankh *);
int	 	 sealed_box(struct ankh *);
int	 	 seckey_read(struct ankh *);
int	 	 seckey_write(struct ankh *);
int	 	 secret_key(struct ankh *);
void	 	 set_algo(struct ankh *);
void	 	 set_algoname(struct ankh *);
void	 	 set_mode(struct ankh *);
char		*str_time(char *, size_t, time_t);
int	 	 stream_decrypt(struct ankh *);
int	 	 stream_encrypt(struct ankh *);
const char	*version(void);

int
main(int argc, char *argv[])
{
	char ch;
	const char *ep;

	if (pledge("cpath getpw rpath stdio tty wpath", NULL) == -1)
		err(1, "pledge");

	if ((adp = calloc(1, sizeof(struct ankh))) == NULL)
		err(1, NULL);

	atexit(cleanup);

	adp->cmd = CMD_UNDEFINED;
	adp->enc = 1;
	adp->cipher_func = stream_encrypt;
	adp->fin = stdin;
	adp->fout = stdout;
	adp->algo = crypto_pwhash_ALG_DEFAULT;
	adp->mode = DEFAULT_MODE;

	set_algoname(adp);

	if (sodium_init() == -1)
		errx(1, "libsodium init error");

	while ((ch = getopt(argc, argv, "BGHKPSVa:dk:m:p:s:v")) != -1) {
		switch (ch) {
		case 'B':
			if (adp->cmd != CMD_UNDEFINED)
				usage();
			adp->cmd = CMD_SEALED_BOX;
			break;
		case 'G':
			if (adp->cmd != CMD_UNDEFINED)
				usage();
			adp->cmd = CMD_GENERATE_KEY_PAIR;
			break;
		case 'S':
			if (adp->cmd != CMD_UNDEFINED)
				usage();
			adp->cmd = CMD_SECRET_KEY;
			break;
		case 'P':
			if (adp->cmd != CMD_UNDEFINED)
				usage();
			adp->cmd = CMD_PUBLIC_KEY;
			break;
		case 'V':
			if (adp->cmd != CMD_UNDEFINED)
				usage();
			adp->cmd = CMD_VERSION;
			break;
		case 'a':
			strlcpy(adp->algoname, optarg, sizeof(adp->algoname));
			set_algo(adp);
			break;
		case 'd':
			adp->cipher_func = stream_decrypt;
			adp->enc = 0;
			break;
		case 'k':
			strlcpy(adp->keyfile, optarg, sizeof(adp->keyfile));
			break;
		case 'm':
			adp->mode = strtonum(optarg, 1, 3, &ep);
			if (ep != NULL)
				errx(1, "mode %s", ep);
			break;
		case 'p':
			strlcpy(adp->pubfile, optarg, sizeof(adp->pubfile));
			break;
		case 's':
			strlcpy(adp->secfile, optarg, sizeof(adp->secfile));
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

	do_command(adp);

	exit(EXIT_SUCCESS);
}

void
usage(void)
{
	/*
	 * -B Sealed Box
	 * -G Generate Key Pair
	 * -P Public Key
	 * -S Secret Key
	 * -V Version
	 */
	fprintf(stderr, "usage:"
	    "\t%1$s -B [-a algo] [-d] [-k keyfile] [-s seckey] -p pubkey\n"
	    "\t%1$s -G [-a algo] [-k keyfile] [-m mode] -p pubkey -s seckey\n"
	    "\t%1$s -P [-a algo] [-d] [-k keyfile] -p pubkey -s seckey\n"
	    "\t%1$s -S [-a algo] [-d] [-k keyfile] [-m mode]\n"
	    "\t%1$s -V\n",
	    getprogname());

	exit(EXIT_FAILURE);
}

void
cleanup(void)
{
	freezero(adp, sizeof(struct ankh));
}

int
data_write(FILE *fp, char *name, void *data, size_t size)
{
	char *hex;
	size_t hexsize;

	hexsize = size * 2 + 1;
	if ((hex = malloc(hexsize)) == NULL)
		err(1, NULL);
	sodium_bin2hex(hex, hexsize, data, size);
	fprintf(fp, "%s: %s\n", name, hex);
	free(hex);

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
		set_mode(a);
		generate_key_pair(a);
		break;
	case CMD_PUBLIC_KEY:
		public_key(a);
		break;
	case CMD_SEALED_BOX:
		sealed_box(a);
		break;
	case CMD_SECRET_KEY:
		set_mode(a);
		secret_key(a);
		break;
	case CMD_VERSION:
		printf("%s %s (libsodium %s)\n", getprogname(),
		    version(), sodium_version_string());
		break;
	}

	return 0;
}

int
generate_key_pair(struct ankh *a)
{
	crypto_box_keypair(a->pubkey, a->seckey);

	seckey_write(a);
	explicit_bzero(a->seckey, sizeof(a->seckey));
	pubkey_write(a);

	return 0;
}

char *
getid(char *str, size_t size)
{
	char *user;
	char host[STRING_MAX];
	struct passwd *pw;
	uid_t uid;

	memset(str, 0, size);
	if (gethostname(host, sizeof(host)) == -1)
		err(1, NULL);
	uid = getuid();
	pw = getpwuid(uid);
	user = pw ? pw->pw_name : "unknown";
	snprintf(str, size, "%s@%s", user, host);

	return str;
}

int
header_read(struct ankh *a)
{
	char sver[STRING_MAX];
	char ver[STRING_MAX];
	const char *cur_ver;
	const char *lib_ver;
	enum command cmd;
	int n;
	unsigned char params[HEADER_PARAM_SIZE + 1];
	unsigned m[MAGIC_LEN];

	cur_ver = version();
	lib_ver = sodium_version_string();
	memset(params, 0, sizeof(params));

	/* Magic. */
	if (fread(m, MAGIC_LEN, 1, a->fin) != 1)
		errx(1, "failure to read header magic");

	if (memcmp(m, v2, MAGIC_LEN) == 0)
		errx(1, "deprecated v2.x.x file detected, use older version");

	if (memcmp(m, magic, MAGIC_LEN) != 0)
		errx(1, "invalid file");

	/* Parameters. */
	if (fread(params, HEADER_PARAM_SIZE, 1, a->fin) != 1)
		errx(1, "failure to read header parameters");

	if ((n = sscanf(params, "%32s %32s %d %d %llu %ld",
	    ver, sver, &cmd, &a->algo, &a->opslimit, &a->memlimit)) != 6)
		errx(1, "invalid number of parameters %d", n);

	/* XXX strict version check. */
	if (strcmp(ver, cur_ver) != 0 || strcmp(sver, lib_ver) != 0)
		warnx("data generated from v%s (libsodium %s)", ver, sver);

	/* Make sure the file type matches the command we are running. */
	if (a->cmd != cmd)
		errx(1, "invalid command for file type %d", cmd);

	if (a->cmd == CMD_SECRET_KEY)
		set_algo(a);

	return 0;
}

int
header_write(struct ankh *a)
{
	const char *cur_ver;
	const char *lib_ver;
	size_t len;
	unsigned char params[HEADER_PARAM_SIZE + 1];

	cur_ver = version();
	lib_ver = sodium_version_string();
	memset(params, 0, sizeof(params));

	if (fwrite(magic, MAGIC_LEN, 1, a->fout) != 1)
		errx(1, "failure to write header magic");

	len = snprintf(params, sizeof(params), "%s %s %d %d %llu %ld",
	    cur_ver, lib_ver, a->cmd, a->algo, a->opslimit, a->memlimit);
	if (len > HEADER_PARAM_SIZE)
		errx(1, "header params exceed size limit %ld", len);

	if (fwrite(params, HEADER_PARAM_SIZE, 1, a->fout) != 1)
		errx(1, "failure to write header params");

	return 0;
}

int
kdf(unsigned char *key, char *keyfile, unsigned char *salt, int algo,
    unsigned long long opslimit, size_t memlimit, int confirm)
{
	char passwd[PASSWD_MAX];

	if (keyfile && keyfile[0] != '\0')
		passwd_read_file(passwd, sizeof(passwd), keyfile);
	else
		passwd_read_tty(passwd, sizeof(passwd), confirm);

	if (crypto_pwhash(key, crypto_secretbox_KEYBYTES, passwd,
	    strlen(passwd), salt, opslimit, memlimit, algo) != 0)
		errx(1, "crypto_pwhash error (check memory limits)");

	explicit_bzero(passwd, sizeof(passwd));

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

int
passwd_read_file(char *pass, size_t size, char *fname)
{
	FILE *fp;
	char *line;
	int linecount;
	size_t linesize;
	size_t passlen;
	ssize_t linelen;

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
		linecount++;
	}

	if (linecount > 1)
		errx(1, "%s contains multiple lines (%d)", fname, linecount);

	passlen = strlen(pass);

	if (passlen == 0)
		errx(1, "please provide a password");

	if (passlen < PASSWD_MIN)
		errx(1, "password too small");

	freezero(line, linesize);

	if (ferror(fp))
		err(1, "%s", fname);

	fclose(fp);

	return 0;
}

int
passwd_read_tty(char *pass, size_t size, int confirm)
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

void
print_value(char *name, unsigned char *bin, int size)
{
	char hex[MAX_LINE];

	sodium_bin2hex(hex, sizeof(hex), bin, size);
	fprintf(stderr, "%s = %s\n", name, hex);
	explicit_bzero(hex, sizeof(hex));
}

int
pubkey_read(struct ankh *a)
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
pubkey_write(struct ankh *a)
{
	FILE *fp;
	char id[STRING_MAX];
	char now[STRING_MAX];
	time_t t;

	memset(id, 0, sizeof(id));

	if ((fp = fopen(a->pubfile, "w")) == NULL)
		err(1, "%s", a->pubfile);

	time(&t);
	str_time(now, sizeof(now), t);
	getid(id, sizeof(id));

	fprintf(fp, "# %s public key\n", getprogname());
	fprintf(fp, "date: %s\n", now);
	fprintf(fp, "version: %s\n", version());
	fprintf(fp, "libsodium: %s\n", sodium_version_string());
	fprintf(fp, "user: %s\n", id);
	data_write(fp, "key", a->pubkey, sizeof(a->pubkey));

	fclose(fp);

	return 0;
}

int
public_key(struct ankh *a)
{
	size_t ctlen;
	unsigned char *ct;
	unsigned char nonce[crypto_box_NONCEBYTES];

	ctlen = sizeof(a->key) + crypto_box_MACBYTES;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);
	memset(ct, 0, ctlen);

	pubkey_read(a);
	seckey_read(a);

	if (a->enc) {
		header_write(a);
		arc4random_buf(a->key, sizeof(a->key));
		arc4random_buf(nonce, sizeof(nonce));
		/* Encrypt cipher key. */
		if (crypto_box_easy(ct, a->key, sizeof(a->key), nonce,
		    a->pubkey, a->seckey) != 0)
			err(1, "crypto_box_easy");
		if (fwrite(nonce, sizeof(nonce), 1, a->fout) != 1)
			err(1, NULL);
		if (fwrite(ct, ctlen, 1, a->fout) != 1)
			err(1, NULL);
	} else {
		header_read(a);
		if (fread(nonce, sizeof(nonce), 1, a->fin) != 1)
			err(1, NULL);
		if (fread(ct, ctlen, 1, a->fin) != 1)
			err(1, NULL);
		/* Decrypt cipher key. */
		if (crypto_box_open_easy(a->key, ct, ctlen, nonce,
		    a->pubkey, a->seckey) != 0)
			errx(1, "crypto_box_easy_open");
	}

	explicit_bzero(a->seckey, sizeof(a->seckey));
	free(ct);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	a->cipher_func(a);

	return 0;
}

int
sealed_box(struct ankh *a)
{
	size_t ctlen;
	unsigned char *ct;

	ctlen = sizeof(a->key) + crypto_box_SEALBYTES;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);
	memset(ct, 0, ctlen);

	pubkey_read(a);

	if (a->enc) {
		header_write(a);
		arc4random_buf(a->key, sizeof(a->key));
		/* Encrypt cipher key. */
		crypto_box_seal(ct, a->key, sizeof(a->key), a->pubkey);
		if (fwrite(ct, ctlen, 1, a->fout) != 1)
			err(1, "failure to write sealed box");
	} else {
		header_read(a);
		if (fread(ct, ctlen, 1, a->fin) != 1)
			err(1, "failure to read sealed box");
		seckey_read(a);
		/* Decrypt cipher key. */
		if (crypto_box_seal_open(a->key, ct, ctlen,
		    a->pubkey, a->seckey) != 0)
			errx(1, "crypto_box_seal_open error");
		explicit_bzero(a->seckey, sizeof(a->seckey));
	}

	free(ct);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	a->cipher_func(a);

	return 0;
}

int
seckey_read(struct ankh *a)
{
	FILE *fp;
	char *line;
	const char *ep;
	const char *name;
	size_t ctlen;
	size_t linesize;
	size_t memlimit;
	ssize_t linelen;
	struct nvp *np;
	struct nvplist lines;
	unsigned char *ct;
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES];
	unsigned long long opslimit;

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
	name = "algo";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	strlcpy(a->algoname, np->value, sizeof(a->algoname));
	set_algo(a);

	name = "opslimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	opslimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "opslimit %s", ep);

	name = "memlimit";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	memlimit = strtonum(np->value, 1, LONG_MAX, &ep);
	if (ep != NULL)
		errx(1, "memlimit %s", ep);

	name = "salt";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	if (sodium_hex2bin(salt, sizeof(salt), np->value, strlen(np->value),
	    NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "nonce";
	if (nvp_find(name, &lines, &np) != 0)
		errx(1, "missing %s in %s", name, a->secfile);
	if (sodium_hex2bin(nonce, sizeof(nonce), np->value,
	    strlen(np->value), NULL, NULL, NULL) != 0)
		errx(1, "invalid data: %s", np->value);

	name = "encrypted key";
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

	kdf(key, a->keyfile, salt, a->algo, opslimit, memlimit, 0);

	/* Decrypt the secret key. */
	if (crypto_secretbox_open_easy(a->seckey, ct, ctlen, nonce, key) != 0)
		errx(1, "invalid passphrase");

	/* Clear key from memory. */
	explicit_bzero(key, sizeof(key));

	free(ct);

	return 0;
}

int
seckey_write(struct ankh *a)
{
	FILE *fp;
	char id[STRING_MAX];
	char now[STRING_MAX];
	mode_t mask;
	size_t ctlen;
	time_t t;
	unsigned char *ct;
	unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	unsigned char salt[crypto_pwhash_SALTBYTES];

	mask = umask(077);

	/* Open secret key file. */
	if ((fp = fopen(a->secfile, "w")) == NULL)
		err(1, "%s", a->secfile);

	/* Allocate ciphertext. */
	ctlen = sizeof(a->seckey) + crypto_secretbox_MACBYTES;
	if ((ct = malloc(ctlen)) == NULL)
		err(1, NULL);

	/* Random nonce and salt. */
	arc4random_buf(nonce, sizeof(nonce));
	arc4random_buf(salt, sizeof(salt));

	kdf(key, a->keyfile, salt, a->algo, a->opslimit, a->memlimit, 1);

	/* Encrypt secret key. */
	crypto_secretbox_easy(ct, a->seckey, sizeof(a->seckey), nonce, key);
	explicit_bzero(key, sizeof(key));

	/* Write our secret key file. */
	time(&t);
	str_time(now, sizeof(now), t);
	getid(id, sizeof(id));
	fprintf(fp, "# %s secret key\n", getprogname());
	fprintf(fp, "date: %s\n", now);
	fprintf(fp, "version: %s\n", version());
	fprintf(fp, "libsodium: %s\n", sodium_version_string());
	fprintf(fp, "user: %s\n", id);
	fprintf(fp, "algo: %s\n", a->algoname);
	fprintf(fp, "opslimit: %llu\n", a->opslimit);
	fprintf(fp, "memlimit: %ld\n", a->memlimit);
	data_write(fp, "salt", salt, sizeof(salt));
	data_write(fp, "nonce", nonce, sizeof(nonce));
	data_write(fp, "encrypted key", ct, ctlen);

	free(ct);
	fclose(fp);

	umask(mask);

	return 0;
}

int
secret_key(struct ankh *a)
{
	unsigned char salt[crypto_pwhash_SALTBYTES];

	if (a->enc) {
		header_write(a);
		arc4random_buf(salt, sizeof(salt));
		if (fwrite(salt, sizeof(salt), 1, a->fout) != 1)
			errx(1, "failure to write salt");
	} else {
		header_read(a);
		if (fread(salt, sizeof(salt), 1, a->fin) != 1)
			errx(1, "failure to read salt");
	}

	kdf(a->key, a->keyfile, salt, a->algo, a->opslimit, a->memlimit,
	    a->enc);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	a->cipher_func(a);

	return 0;
}

void
set_algo(struct ankh *a)
{
	int i;
	int max;
	struct kdfinfo *ki;

	max = sizeof(kdflist) / sizeof(struct kdfinfo);
	for (i = 0; i < max; i++) {
		ki = &kdflist[i];
		if (strcmp(a->algoname, ki->name) == 0) {
			a->algo = ki->algo;
			return;
		}
	}
	errx(1, "undefined algo name %s", a->algoname);
}

void
set_algoname(struct ankh *a)
{
	int i;
	int max;
	struct kdfinfo *ki;

	max = sizeof(kdflist) / sizeof(struct kdfinfo);
	for (i = 0; i < max; i++) {
		ki = &kdflist[i];
		if (a->algo == ki->algo) {
			strlcpy(a->algoname, ki->name, sizeof(a->algoname));
			return;
		}
	}
	errx(1, "undefined algo value %d", a->algo);
}

/*
 * Set the mode.
 * 1) Interactive 2) Moderate 3) Sensitive
 * This will set parameters for the key derivation function.
 * See libsodium crypto_pwhash documentation.
 */
void
set_mode(struct ankh *a)
{
	switch (a->mode) {
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
		errx(1, "undefined mode %d", a->mode);
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

int
stream_decrypt(struct ankh *a)
{
	crypto_secretstream_xchacha20poly1305_state st;
	int eof;
	size_t inlen;
	size_t outlen;
	size_t rlen;
	unsigned char *in;
	unsigned char *out;
	unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char tag;
	unsigned long long wlen;

	memset(&hdr, 0, sizeof(hdr));
	memset(&st, 0, sizeof(st));

	inlen = BUFSIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
	if ((in = malloc(inlen)) == NULL)
		err(1, NULL);
	outlen = BUFSIZE;
	if ((out = malloc(outlen)) == NULL)
		err(1, NULL);

	fread(hdr, sizeof(hdr), 1, a->fin);
	if (ferror(a->fin))
		errx(1, "error reading from input stream");

	if (crypto_secretstream_xchacha20poly1305_init_pull(&st,
	    hdr, a->key) != 0)
		errx(1, "invalid header");

	do {
		rlen = fread(in, 1, inlen, a->fin);
		if (ferror(a->fin))
			errx(1, "error reading from input stream");
		eof = feof(a->fin);
		if (crypto_secretstream_xchacha20poly1305_pull(&st, out, &wlen,
		    &tag, in, rlen, NULL, 0) != 0)
			errx(1, "invalid data");
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
		    && !eof)
			errx(1, "premature end of file reached");
		if (fwrite(out, wlen, 1, a->fout) == 0)
			errx(1, "error writing to output stream");
	} while (!eof);

	freezero(out, outlen);
	freezero(in, inlen);

	return 0;
}

int
stream_encrypt(struct ankh *a)
{
	crypto_secretstream_xchacha20poly1305_state st;
	int eof;
	size_t inlen;
	size_t outlen;
	size_t rlen;
	unsigned long long wlen;
	unsigned char *in;
	unsigned char *out;
	unsigned char hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char tag;

	memset(&hdr, 0, sizeof(hdr));
	memset(&st, 0, sizeof(st));

	inlen = BUFSIZE;
	if ((in = malloc(inlen)) == NULL)
		err(1, NULL);
	outlen = BUFSIZE + crypto_secretstream_xchacha20poly1305_ABYTES;
	if ((out = malloc(outlen)) == NULL)
		err(1, NULL);

	crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, a->key);

	if (fwrite(hdr, sizeof(hdr), 1, a->fout) == 0)
		errx(1, "error writing to output stream");

	do {
		rlen = fread(in, 1, inlen, a->fin);
		if (ferror(a->fin))
			errx(1, "error reading from input stream");
		eof = feof(a->fin);
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		crypto_secretstream_xchacha20poly1305_push(&st, out, &wlen,
		    in, rlen, NULL, 0, tag);
		if (fwrite(out, wlen, 1, a->fout) == 0)
			errx(1, "error writing to output stream");
	} while (!eof);

	freezero(out, outlen);
	freezero(in, inlen);

	return 0;
}

const char *
version(void)
{
	static char v[STRING_MAX];

	if (v[0] == '\0')
		snprintf(v, sizeof(v), "%d.%d.%d", MAJ, MIN, REV);

	return v;
}
