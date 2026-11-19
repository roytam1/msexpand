/*
 * main.c -- standalone driver for wimlib 1.14.5's ORIGINAL LZMS block
 * decompressor, compiled with MSVC6 (VC98).
 *
 * Usage: ref_lzms.exe <compressed.bin> <uncompressed_size> [expected.bin]
 *
 * The original lzms_decompress.c is #included so its static entry points are
 * directly callable; its algorithm is untouched apart from the handful of
 * C89 syntax adaptations documented in the copied sources.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzms_decompress.c"

/* Implementations of the two util.h shim routines used above.  Windows'
 * malloc() already returns suitably aligned memory for the scalar codec. */
void *
wimlib_aligned_malloc(size_t size, size_t alignment)
{
	(void)alignment;
	return malloc(size);
}

void
wimlib_aligned_free(void *ptr)
{
	free(ptr);
}

static u8 *
read_whole_file(const char *path, size_t *size_out)
{
	FILE *fp;
	long len;
	u8 *buf;

	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "cannot open %s\n", path);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET) != 0)
	{
		fprintf(stderr, "cannot determine size of %s\n", path);
		fclose(fp);
		return NULL;
	}
	buf = (u8 *)malloc((size_t)len + 1);
	if (!buf) {
		fclose(fp);
		return NULL;
	}
	if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		fprintf(stderr, "short read on %s\n", path);
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	*size_out = (size_t)len;
	return buf;
}

static void
print_hex(const char *label, const u8 *p, size_t n)
{
	size_t i;

	printf("%s:", label);
	for (i = 0; i < n; i++)
		printf(" %02X", p[i]);
	printf("\n");
}

int
main(int argc, char **argv)
{
	const char *comp_path;
	const char *expected_path;
	char *endp = NULL;
	unsigned long size_ul;
	size_t out_size;
	size_t in_size;
	size_t exp_size;
	u8 *comp;
	u8 *out;
	u8 *expected;
	void *d;
	int ret;
	int diff;
	size_t i;
	size_t n;

	if (argc < 3) {
		fprintf(stderr,
			"usage: %s <compressed.bin> <uncompressed_size> [expected.bin]\n",
			argv[0]);
		return 2;
	}
	comp_path = argv[1];
	size_ul = strtoul(argv[2], &endp, 0);
	if (endp == argv[2] || size_ul == 0 || size_ul > 0x7fffffffUL) {
		fprintf(stderr, "bad uncompressed size: %s\n", argv[2]);
		return 2;
	}
	out_size = (size_t)size_ul;
	expected_path = (argc >= 4) ? argv[3] : NULL;

	comp = read_whole_file(comp_path, &in_size);
	if (!comp)
		return 2;
	out = (u8 *)malloc(out_size);
	if (!out) {
		free(comp);
		return 2;
	}
	memset(out, 0, out_size);

	d = NULL;
	ret = lzms_create_decompressor(out_size, &d);
	if (ret != 0) {
		fprintf(stderr, "create_decompressor failed: %d\n", ret);
		free(out);
		free(comp);
		return 1;
	}
	ret = lzms_decompress(comp, in_size, out, out_size, d);
	lzms_free_decompressor(d);

	printf("compressed=%s (%lu bytes), size=%lu, decompress_ret=%d\n",
	       comp_path, (unsigned long)in_size, size_ul, ret);

	n = out_size < 16 ? out_size : 16;
	print_hex("first16", out, n);

	if (ret != 0) {
		printf("RESULT: DECOMPRESS FAILED\n");
		free(out);
		free(comp);
		return 1;
	}

	if (!expected_path) {
		fwrite(out, 1, out_size, stdout);
		free(out);
		free(comp);
		return 0;
	}

	expected = read_whole_file(expected_path, &exp_size);
	if (!expected) {
		free(out);
		free(comp);
		return 2;
	}
	printf("expected=%s (%lu bytes)\n", expected_path, (unsigned long)exp_size);
	print_hex("expect16", expected, exp_size < 16 ? exp_size : 16);

	diff = (exp_size != out_size);
	if (!diff) {
		for (i = 0; i < out_size; i++) {
			if (out[i] != expected[i]) {
				diff = 1;
				printf("first difference at byte %lu: got %02X expected %02X\n",
				       (unsigned long)i, out[i], expected[i]);
				break;
			}
		}
	}
	printf("RESULT: %s\n", diff ? "DIFF" : "MATCH");

	free(expected);
	free(out);
	free(comp);
	return diff ? 1 : 0;
}
