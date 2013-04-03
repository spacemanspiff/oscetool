#ifndef __SPP_H_
#define __SPP_H_

#include "self.h"

#define SPP_HEADER_NO_DATA_LEN 56

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint16_t unk1;
	uint16_t format_version;
	uint32_t spp_size;
	uint32_t unk3;
	uint32_t unk4;
	uint64_t unk5;
	uint32_t entry_count;
	uint32_t unk7;
} spp_header_t;

typedef struct {
	uint32_t size;
	uint32_t type;
	uint64_t lpar_authid;
	uint64_t prog_authid;
	uint8_t name[32];
	uint8_t data;
} spp_entry_t;

void print_spp(FILE *out, sce_info_t *sce_info);
int write_spp(const char *filename, sce_info_t *sce_info);

#ifdef __cplusplus
}
#endif

#endif
