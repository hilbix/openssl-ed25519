/* This Works is placed under the terms of the Copyright Less License,
 * see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.
 *
 * This was written from scratch while looking on OpenSSL example code.
 * Except for error processing (I do not grok how OpenSSL is used here),
 * this code tries to stick to what is available in OpenSSL (like BIOs).
 * So hopefully the code is free of Copyright or IP by others.
 * This does not apply to the binary, as this links in code of others!
 *
 * ./ed25519 file pubkey privkey	# create and verify sig
 * ./ed25519 file pubkey		# verify sig
 *
 * Tested to work with OpenSSL v1.1.1f
 */

#define	_GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

/* bail out if something fails */
#define	KO(ko,...)	do { if (ko) OOPS("OOPS:", __VA_ARGS__, NULL); } while (0)
static void
OOPS(const char *s, ...)
{
  const char	*sep="";
  va_list	list;
  int		e = errno;

  for (va_start(list, s); s; s=va_arg(list, const char *))
    {
      fprintf(stderr, "%s%s", sep, s);
      sep	= " ";
    }
  if (e)
    fprintf(stderr, ": %s", strerror(e));
  fprintf(stderr, "\n");
  exit(23); abort(); for (;;);
}

static const char	OOM[] =	"out of memory";

/* ensure memory allocated	*/
static void *
alloc(size_t len)
{
  void *ptr;

  ptr	= OPENSSL_malloc(len);
  KO(!ptr, OOM);
  return ptr;
}

static BIO *
mem_BIO(void)
{
  BIO	*bio;

  bio	= BIO_new(BIO_s_mem());
  KO(!bio, "cannot create memory buffer");
  return bio;
}

static BIO *
stdout_BIO(void)
{
  static BIO	*bio;

  if (!bio)
    bio	= BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
  KO(!bio, "cannot write to stdout");
  return bio;
}

/* Read file entirely into memory BIO.
 */
static BIO *
file_read_bin(const char *name)
{
  BIO		*bio, *r;
  char		tmp[BUFSIZ];

  if (name && strcmp(name, "-"))
    r	= BIO_new_file(name, "rb");
  else
    r	= BIO_new_fp(stdin, BIO_CLOSE);
  KO(!r, "cannot read", name);

  bio	= mem_BIO();
  while (!BIO_eof(r))
    {
      int got;

      got	= BIO_read(r, tmp, sizeof tmp);
      KO(got<0, "read error:", name);
      BIO_write(bio, tmp, got);
    }
  BIO_free(r);
  return bio;
}

static const char PRIVKEY[]	= "private key";
static const char PUBKEY[]	= "public key";

static EVP_PKEY *
key_read(const char *name, const char *type)
{
  BIO		*bio;
  EVP_PKEY	*key;

  bio	= BIO_new_file(name, "r");
  if (type == PRIVKEY)
    key	= PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  else	/* do we really have to distinguish here?!?	*/
    key	= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  /* XXX TODO XXX: we should be able to derive the public key from private key
   * Read:
   * PEM_read_bio_PUBKEY() fails if it must read a Private Key.  But:
   * PEM_read_bio_PrivateKey() returns a Private Key (at least that is what I see on OpenSSL 1.1.1f).
   * So if _PUBKEY() fails we could retry with _PrivateKey as a last resort.
   * But leave this as is, as a feature that you need to give the correct file.
   */
  KO(!key, "cannot read", type);
  BIO_free(bio);

  switch (EVP_PKEY_base_id(key))
    {
      default:
        OOPS("wrong key type: ED25519", type, "expected in:", name);

      // perhaps support others in future?
      case EVP_PKEY_ED25519:
        break;
    }

  /* I found no proper way to check features of EVP_PKEY, except by reading them.
   *
   * You must fully read them, as the NULL variant always returns success for unknown reason.
   *
   * Perhaps this is not needed at all as PEM_read_bio_PrivateKey() and PEM_read_bio_PUBKEY() already ensure this.
   * But I did not find such a guarantee in the documentation.
   */
  if (type == PRIVKEY)
    {
      size_t len;
      unsigned char *tmp;
      KO(1 != EVP_PKEY_get_raw_private_key(key, NULL, &len), "private key missing in:", name);	/* cannot fail?!?	*/
      tmp	= alloc(len);
      KO(1 != EVP_PKEY_get_raw_private_key(key, tmp, &len), "private key missing in:", name);
      OPENSSL_free(tmp);

      /* XXX TODO XXX issue a warning if no public key is found?	*/
#if 0
      /* succeeds even on the private key.
       * Is this a guaranteed feature that when reading a private key
       * the public key is available as well?  Always?
       */
      KO(1 != EVP_PKEY_get_raw_public_key(key, NULL, &len), "public key missing in:", name);
      tmp	= alloc(len);
      KO(1 != EVP_PKEY_get_raw_public_key(key, tmp, &len), "public key missing in:", name);
      OPENSSL_free(tmp);
#endif
    }
  else
    {
      size_t len;
      unsigned char *tmp;
      KO(1 != EVP_PKEY_get_raw_public_key(key, NULL, &len), "public key missing in:", name);
      tmp	= alloc(len);
      KO(1 != EVP_PKEY_get_raw_public_key(key, tmp, &len), "public key missing in:", name);
      OPENSSL_free(tmp);

      /* XXX TODO XXX issue a warning if a private key is found?
       *
       * AFAICS this cannot happen, as PEM_read_bio_PUBKEY() above fails for private keys.
       */
#if 0
      KO(1 != EVP_PKEY_get_raw_private_key(key, NULL, &len), "private key missing in:", name);
      tmp	= alloc(len);
      KO(1 != EVP_PKEY_get_raw_private_key(key, tmp, &len), "XX private key missing in:", name);
      OPENSSL_free(tmp);
#endif
    }
  return key;
}

/* Sign buffer with private key
 * and write signature to BIO sig as base64
 */
static void
ed25519_sign(EVP_PKEY *priv, BIO *data, BIO *sig, EVP_MD *md)
{
  size_t	len1, len2;
  unsigned char	*buf, *ptr;
  long		total;
  EVP_MD_CTX	*ctx;
  int		rc;

  total	= BIO_get_mem_data(data, &ptr);
  ctx	= EVP_MD_CTX_new();
  KO(!ctx, OOM);

  rc	= EVP_DigestSignInit(ctx, NULL, md, NULL, priv);
  KO(rc != 1, "cannot initialize signing");
  rc	= EVP_DigestSign(ctx, NULL, &len1, ptr, total);
  KO(rc != 1 || len1<1, "cannot sign");
  buf	= alloc(len1);
  rc	= EVP_DigestSign(ctx, buf, &len2, ptr, total);
  KO(rc != 1 || len1 != len2, "signing failed");

#if 0
  BIO_dump(stdout_BIO(), (char *)buf, len1);
#endif
#if 0
  BIO_write(sig, buf, len1);
#else
  BIO	*bio;

  bio	= BIO_new(BIO_f_base64());
  KO(!bio, "cannot create base64 encoding");
  KO(bio != BIO_push(bio, sig), "BIO_push() failed");

  BIO_write(bio, buf, len1);

  BIO_flush(bio);
  BIO_pop(bio);
  BIO_free(bio);
#endif

  OPENSSL_free(buf);
  EVP_MD_CTX_free(ctx);
}

#define	MAGIC0	"// "				/* this should be configurable	*/
#define	MAGIC1	"Begin signature block\n"	/* actually uses the wording found at Microsoft	*/
#define	MAGIC2	"End signature block\n"		/* actually uses the wording found at Microsoft	*/

/* print the signature such, that it can be added to files at the end
 * Relies on MAGIC0 as comment characters.
 * We probably should support others, too.
 *
 * **This needs a memory BIO!**
 */
static void
sig_print(BIO *out, BIO *sig)
{
  unsigned const char	*buf;
  long			max, n;

  BIO_puts(out, MAGIC0);
  BIO_puts(out, MAGIC1);
  for (max=BIO_get_mem_data(sig, &buf); max>0; BIO_write(out, buf, n), buf+=n, max-=n)
    {
      const unsigned char *lf;

      BIO_puts(out, MAGIC0);
      lf	= memchr(buf, '\n', max);
      if (lf)
        {
          n	= lf-buf+1;
          continue;
        }
      /* just in case the buffer does not end on '\n'	*/
      BIO_write(out, buf, max);
      BIO_write(out, "\n", 1);
      break;
    }
  BIO_puts(out, MAGIC0);
  BIO_puts(out, MAGIC2);
}

/* Extract the signature at the end of buf
 * and return the shortened length
 */
static size_t
sig_extract(BIO *data, BIO *sig, const char *name)
{
  size_t	n;
  unsigned char	*buf, *ptr, *end;
  long		len;

  len	= BIO_get_mem_data(data, &buf);

  /* check end of signature	*/
  n	= (sizeof MAGIC0 MAGIC2)-1;
  KO(len<=n || memcmp(buf+(len-=n), MAGIC0 MAGIC2, n), "no signature at end of:", name);

  /* the problem here is that we cannot write BIOs in reverse,
   * hence search for start of signature.
   * Note that this could be improved by a reverse Boyer Moore search.
   */
  end	= buf+len;
  n	= (sizeof MAGIC0 MAGIC1)-1-1;
  for (;;)
    {
      ptr	= memrchr(buf, '\n', len);	/* find next \n, as MAGIC1 ends on \n, too	*/
      KO(!ptr || (len = ptr - buf) < n, "signature start marker not found in:", name);
      if (!memcmp(ptr-n, MAGIC0 MAGIC1, n))	/* n is correct here, as MAGIC0 MAGIC1[n] == '\n'	*/
        break;
    }
  len	-= n;
  /* ptr is on the '\n' of the signature start marker	*/
  for (ptr++; ptr < end; )
    {
      unsigned char	*tmp;

      KO(memcmp(ptr, MAGIC0, sizeof MAGIC0-1), "invalid formatted signature");
      tmp	= ptr + sizeof MAGIC0-1;
      ptr	= memchr(ptr, '\n', end-ptr);
      KO(!ptr, "invalid formatted signature");
      BIO_write(sig, tmp, ++ptr-tmp);
    }
  return len;
}

/* Read base64 encoded signature from BIO sig
 * and verify memory BIO data with the public key.
 * Use -1 as limit to verify the complete data.
 */
static int
ed25519_verify(EVP_PKEY *pub, BIO *data, size_t limit, BIO *sig, EVP_MD *md)
{
  EVP_MD_CTX	*ctx;
  int		rc;
  unsigned char	*buf, *ptr;
  size_t	max;
  int		len;
  long		total;

  max	= 100;	/* something arbitrary long enough	*/
  buf	= alloc(max);
#if 0
  slen	= BIO_read(sig, sbuf, max);
#else
  BIO	*bio;

  bio	= BIO_new(BIO_f_base64());
  KO(!bio, "cannot create base64 encoding");
  KO(bio != BIO_push(bio, sig), "BIO_push() failed");

  len	= BIO_read(bio, buf, max);

  BIO_pop(bio);
  BIO_free(bio);
#endif
#if 0
  BIO_dump(stdout_BIO(), (char *)sbuf, slen);
#endif
  KO(len<1, "cannot read signature");
  KO(len >= max, "signature too long");

  ctx	= EVP_MD_CTX_new();
  KO(!ctx, OOM);

  rc	= EVP_DigestVerifyInit(ctx, NULL, md, NULL, pub);
  KO(rc != 1, "cannot initialize verify");

  total	= BIO_get_mem_data(data, &ptr);
  rc	= EVP_DigestVerify(ctx, buf, (size_t)len, ptr, limit<total ? limit : total);

  EVP_MD_CTX_free(ctx);
  return rc;
}

int
main(int argc, char **argv)
{
  BIO		*sig, *data;
  size_t	limit;

  if (argc < 3 || argc > 4)
    {
      fprintf(stderr, "Usage: %s file pubkey [privkey]\n"
              "\tcreate signature with privkey (if given),\n"
              "\telse read signature from end of file.\n"
              "\tAlways verifies signature against pubkey.\n"
              "\t(warning: file is read in memory entirely)\n"
              , argv[0]);
      exit(42);
    }

  /* sig keeps the signature:
   * Either read from file
   * or created by signing
   */
  sig	= mem_BIO();
  data	= file_read_bin(argv[1]);

  if (argc == 4)
    {
      EVP_PKEY	*priv;

      /* Generate signature	*/
      priv	= key_read(argv[3], PRIVKEY);
      ed25519_sign(priv, data, sig, NULL);
      EVP_PKEY_free(priv);

      /* Output the generated signature to stdout	*/
      sig_print(stdout_BIO(), sig);
      limit	= -1;
    }
  else
    limit	= sig_extract(data, sig, argv[1]);

  /* Verify signature
   *
   * On signature creation this verifies,
   * that the public key matches the private one.
   * (I think that is important.)
   */
  {
    EVP_PKEY	*pub;

    pub	= key_read(argv[2], PUBKEY);
    KO(1 != ed25519_verify(pub, data, limit, sig, NULL), "signature validation failed");
    EVP_PKEY_free(pub);
  }

  BIO_free(data);
  BIO_free(sig);
  return 0;
}

