#include "util.h"
//#include "platform.h"

#include "polarssl/sha1.h"
#include <zlib.h>

#include "global.h"

void  _hexdump(FILE *out, const char *name, uint32_t offset, uint8_t *buf, int len, int print_addr) {
  int i, j, align = strlen(name) + 1;
  
  fprintf(out, "%s ", name);
  if(print_addr)
    fprintf(out, "%08X: ", offset);
  for(i = 0; i < len; i++)
    {
      if(i % 16 == 0 && i != 0)
	{
	  fprintf(out, "\n");
	  for(j = 0; j < align; j++)
	    fputc(' ', out);
	  if(print_addr)
	    fprintf(out, "%08X: ", offset + i);
	}
      fprintf(out, "%02X ", buf[i]);
    }
  fprintf(out, "\n");
}

int _write_buffer(const char *file, uint8_t *buffer, uint32_t length)
{
  FILE *fp;
  
  if((fp = fopen(file, "wb")) == NULL)
    return 0;
  
  /*while(length > 0)
    {
    uint32_t wrlen = 1024;
    if(length < 1024)
    wrlen = length;
    fwrite(buffer, sizeof(uint8_t), wrlen, fp);
    length -= wrlen;
    buffer += 1024;
    }*/
  
  fwrite(buffer, sizeof(uint8_t), length, fp);
  
  fclose(fp);
  
  return 1;
}

void decompress(uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_len) {
  z_stream s;
  int ret;
  
  memset(&s, 0, sizeof(s));
  
  s.zalloc = Z_NULL;
  s.zfree = Z_NULL;
  s.opaque = Z_NULL;

  ret = inflateInit(&s);
  if (ret != Z_OK) {
    printf("inflateInit returned %d\n", ret);
    exit(-1);
  }

  s.avail_in = in_len;
  s.next_in = in;
  
  s.avail_out = out_len;
  s.next_out = out;
  
  ret = inflate(&s, Z_FINISH);

  if (ret != Z_OK && ret != Z_STREAM_END) {
    printf("inflate returned %d\n", ret);
    exit(-1);
  }

  inflateEnd(&s);
}

const char *id2name(uint64_t id, struct id2name_tbl *t, const char *unk)
{
  while (t->name != NULL) {
    if (id == t->id)
      return t->name;
    t++;
  }
  return unk;
}

uint64_t name2id(const char *name, struct id2name_tbl *t, uint64_t unk) {
  while (t->name != NULL) {
    if (strcmp(name, t->name) == 0)
      return t->id;
    t++;
  }
  return unk;
}

uint64_t x_to_u64(const char *hex) {
  uint64_t result, t;
  uint32_t len;
  int32_t c;
  
  result = 0;
  t = 0;
  len = strlen(hex);
  
  while (len--) {
    c = *hex++;
    if (c >= '0' && c <= '9')
      t = c - '0';
    else if (c >= 'a' && c <= 'f')
      t = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      t = c - 'A' + 10;
    else
      t = 0;
    result |= t << (len * 4);
  }
  
  return result;
}

uint8_t * x_to_u8_buffer(const char *hex) {
  char tmp[3] = { 0, 0, 0 };
  uint8_t *result;
  uint8_t *ptr;
  uint32_t len;
  
  len = strlen(hex);
  if (len % 2 != 0)
    return NULL;
  
  result = (uint8_t *)malloc(len);
  memset(result, 0, len);
  ptr = result;
  
  while (len--) {
    tmp[0] = *hex++;
    tmp[1] = *hex++;
    *ptr++ = (uint8_t)x_to_u64(tmp);
  }
  
  return result;
}


uint8_t *_read_buffer(const char *file, uint32_t *length)
{
  FILE *fp;
  uint32_t size;
  
  if((fp = fopen(file, "rb")) == NULL)
    return NULL;
  
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  
  uint8_t *buffer = (uint8_t *)malloc(sizeof(uint8_t) * size);
  if(fread(buffer, sizeof(uint8_t), size, fp) != (sizeof(uint8_t) * size))
    return NULL;
  
  if(length != NULL)
    *length = size;
  
  fclose(fp);
  
  return buffer;
}


int exists(const char *entry_path) {
  struct stat buffer;
  memset ((void*)&buffer, 0, sizeof(buffer));
  
  int res = stat(entry_path, &buffer);
  
  if (res == 0) {
    return 1;
  }
  return 0;
}

int valid_hex_digit(char c) {
  return  (c >= '0' && c <= '9') ||
    (c >= 'a' || c <= 'f') || (c >= 'A' || c <= 'F');
}

int valid_hex(const char *hexstr) {
  const char *c = hexstr;

  if (!c)
    return 0;

  while (*c) {
    if (!valid_hex_digit(*c))
	return 0;
    ++c;
  }
  return 1;
}


void memcpy_inv(uint8_t *dst, uint8_t *src, uint32_t len) { 
  uint32_t j; 
 
  for (j = 0; j < len; j++) 
    dst[j] = ~src[j]; 
} 

char *read_line(char *s, int size, FILE *stream) {
    *s = '\0';
    if(fgets(s, size, stream) != NULL) {
        int len = strlen(s);
        if (len && s[len-1] == '\n')
          s[len-1] = 0;
        len = strlen(s);
        if (len && s[len-1] == '\r')
          s[len-1] = 0;
    }
    return s;
}

static char *data_env = NULL;
static int initialized_env = 0;

char *get_data_filename(const char *datafile, char *filename) {
  filename[0] = 0;

  if (!initialized_env) {
    data_env = getenv(SCE_DATA_ENV);
    initialized_env = 1;
    if (!exists(data_env)) 
      data_env = NULL;
  }

  if (data_env) {
    sprintf(filename, "%s/%s", data_env, datafile);
    if (exists(filename)) 
	return filename;
  }
  sprintf(filename, "%s/%s", SCE_DATA_DIR, datafile);
  return filename;
}
