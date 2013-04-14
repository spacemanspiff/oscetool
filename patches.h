#ifndef _PATCHES_H_
#define _PATCHES_H_

#include "types.h"

#define PH_TYPE_SYS_PROCESS_SPAWN        0x60000001
#define SYS_PROCESS_SPAWN_MAGIC          0x13bcc5f6
#define SYS_PROCESS_SPAWN_MAGIC_ALT      0x1b434cec

#include "self.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	uint32_t sdk_version;
} patch_options_t;

typedef struct _sys_process_param {
	uint32_t size;
	uint32_t magic;
	uint32_t version;
	uint32_t sdk_version;
	int32_t prio;
	uint32_t stacksize;
	uint32_t malloc_pagesize;
	uint32_t ppc_seg;
} sys_process_param_t;

int patch_elf(elf_data_t *elf_data, patch_options_t *opts);

#ifdef __cplusplus
}
#endif

#endif
