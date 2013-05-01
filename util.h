#ifndef __UTIL_H_
#define __UTIL_H_

#include "types.h"

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

#define CONFIG_MAX_LINE_SIZE 512

#ifdef __cplusplus
extern "C" {
#endif

struct id2name_tbl {
	uint64_t id;
	const char *name;
};

void  _hexdump(FILE *out, const char *name, uint32_t offset, uint8_t *buf, int len, int print_addr);
int _write_buffer(const char *file, uint8_t *buffer, uint32_t length);
void decompress(uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_len);
const char *id2name(uint64_t id, struct id2name_tbl *t, const char *unk);
uint64_t name2id(const char *name, struct id2name_tbl *t, uint64_t unk);
uint64_t x_to_u64(const char *hex);
uint8_t * x_to_u8_buffer(const char *hex);
uint8_t *_read_buffer(const char *file, uint32_t *length);
int exists(const char *directory_path);
void memcpy_inv(uint8_t *dst, uint8_t *src, uint32_t len);

char *read_line(char *s, int size, FILE *stream);
int valid_hex_digit(char c);
int valid_hex(const char *hexstr);
char *get_data_filename(const char *datafile, char *filename);

#ifdef __cplusplus
}
#endif

#endif 
