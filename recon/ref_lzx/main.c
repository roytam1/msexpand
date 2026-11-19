/*
 * main.c -- standalone driver for wimlib 1.14.5's ORIGINAL LZX decompressor.
 *
 * Usage: ref_lzx.exe <compressed.bin> <uncompressed_size> <windowBits> [out.bin]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lzx_decompress.c"
const u8 *g_comp_start;

void *wimlib_aligned_malloc(size_t size, size_t alignment)
{
	(void)alignment;
	return malloc(size);
}

void wimlib_aligned_free(void *ptr)
{
	free(ptr);
}

static u8 *read_whole_file(const char *path, size_t *size_out)
{
	FILE *fp;
	long len;
	u8 *buf;

	fp = fopen(path, "rb");
	if (!fp) return NULL;
	if (fseek(fp, 0, SEEK_END) != 0 || (len = ftell(fp)) < 0 ||
	    fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return NULL; }
	buf = (u8 *)malloc((size_t)len + 1);
	if (!buf) { fclose(fp); return NULL; }
	if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		free(buf); fclose(fp); return NULL;
	}
	fclose(fp);
	*size_out = (size_t)len;
	return buf;
}

int main(int argc, char **argv)
{
	u8 *comp, *out, *d = NULL;
	size_t in_size, out_size;
	unsigned long ws;
	void *dmem = NULL;
	int ret;

	if (argc < 4) {
		fprintf(stderr, "usage: %s <compressed.bin> <uncompressed_size> <windowBits> [out.bin]\n", argv[0]);
		return 2;
	}
	out_size = (size_t)strtoul(argv[2], NULL, 0);
	ws = strtoul(argv[3], NULL, 0);
	comp = read_whole_file(argv[1], &in_size);
	if (!comp || out_size == 0 || ws < 15 || ws > 21) return 2;
	out = (u8 *)malloc(out_size);
	if (!out) { free(comp); return 2; }
	memset(out, 0, out_size);

	ret = lzx_create_decompressor((size_t)1 << ws, &dmem);
	if (ret) { fprintf(stderr, "create failed %d\n", ret); return 1; }
	ret = lzx_decompress(comp, in_size, out, out_size, dmem);
	lzx_free_decompressor(dmem);
	printf("ref_lzx: in=%lu out=%lu windowBits=%lu ret=%d\n",
	       (unsigned long)in_size, (unsigned long)out_size, ws, ret);
	if (ret == 0 && argc >= 5) {
		FILE *f = fopen(argv[4], "wb");
		if (f) { fwrite(out, 1, out_size, f); fclose(f); }
	}
	if (ret == 0) {
		size_t i;
		printf("first16:");
		for (i = 0; i < out_size && i < 16; ++i) printf(" %02X", out[i]);
		printf("\n");
	}
	free(comp);
	free(out);
	return ret;
}
