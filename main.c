/*
 *  Copyright (C) 2013, Spaceman Spiff
 *
 *  This file is part of Open SCE Tool.
 *
 *  Open SCE Tool is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Open SCE Tool is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCETool.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "global.h"
#include "backend.h"
#include "util.h"
#include "keys.h"

#include "klics.h"


static int option_valid = 0;
static int cmd_print = 0;
static int cmd_encrypt = 0;
static int cmd_decrypt = 0;
static int cmd_print_keysets = 0;

uint8_t *klicensee;

int verbose = 0;
int raw_output = 0;

char *template_path = NULL;
char *inputfile_path = NULL;
char *outputfile_path = NULL;
char *meta_info_value = NULL;
char *keyset_value = NULL;
char *klicensee_value = NULL;


char *key_revision_value = NULL;
char *auth_id_value = NULL;
char *vendor_id_value = NULL;
char *app_version_value = NULL;
char *fw_version_value = NULL;
char *add_section_headers_value = NULL;
char *skip_sections_value = NULL;
char *self_control_flags_value = NULL;
char *self_capability_flags_value = NULL;
char *sys_process_sdk_version_value = NULL;

char *np_license_type_value = NULL;
char *np_app_type_value = NULL;
char *np_content_id_value = NULL;
char *np_realfilename_value = NULL;
   
char *filetype_value = NULL;
char *selftype_value = NULL;
char *compress_value = NULL;
char *np_add_sig_value = NULL;

static void show_version(void) {
  printf("OpenSCETool " OSCETOOL_VERSION " (C) 2013\n");
  printf("Based on scetool (C) 2011-2012 by naehrwert\n");
  printf("NP local license handling (C) 2012 by flatz\n");
}

void show_usage()
{
  show_version();  
  
  printf("USAGE: oscetool [options] command\n");
  printf("COMMANDS                Parameters            Explanation\n");
  printf(" -h, --help                                   Print this help.\n");
  printf(" -k, --print-keys                             List keys.\n");
  printf(" -i, --print-infos      File-in               Print SCE file info.\n");
  printf(" -d, --decrypt          File-in File-out      Decrypt/dump SCE file.\n");
  printf(" -e, --encrypt          File-in File-out      Encrypt/create SCE file.\n");
  printf("OPTIONS                 Possible Values       Explanation\n");
  printf(" -v, --verbose                                Enable verbose output.\n");
  printf(" -r, --raw                                    Enable raw value output.\n");
  printf(" -t, --template         File-in               Template file (SELF only)\n");
  printf(" -0, --sce-type         SELF/RVK/PKG/SPP      SCE File Type\n");
  printf(" -1, --compress-data    TRUE/FALSE(default)   Whether to compress data or not.\n");
  printf(" -s, --skip-sections    TRUE(default)/FALSE   Whether to skip sections or not.\n");
  printf(" -2, --key-revision     e.g. 00,01,...,0A,... Key Revision\n");
  printf(" -m, --meta-info        64 bytes              Use provided meta info to decrypt.\n");
  printf(" -K, --keyset           32(Key)16(IV)\n");
  printf("                        40(Pub)21(Priv)1(CT)  Override keyset.\n");
  printf(" -3, --self-auth-id     e.g. 1010000001000003 Authentication ID\n");
  printf(" -4, --self-vendor-id   e.g. 01000002         Vendor ID\n");
  printf(" -5, --self-type        LV0/LV1/LV2/APP/ISO/\n");
  printf("                        LDR/NPDRM             SELF Type\n");
  printf(" -A, --self-app-version e.g. 0001000000000000 Application Version\n");
  printf(" -6, --self-fw-version  e.g. 0003004100000000 Firmware Version\n");
  printf(" -7, --self-add-shdrs   TRUE(default)/FALSE   Whether to add ELF shdrs or not.\n");
  printf(" -8, --self-ctrl-flags  32 bytes              Override control flags.\n");
  printf(" -9, --self-cap-flags   32 bytes              Override capability flags.\n");
  printf(" -b, --np-license-type  LOCAL/FREE            License Type\n");
  printf(" -c, --np-app-type      SPRX/EXEC/USPRX/UEXEC App Type (U* for updates)\n");
  printf(" -f, --np-content-id                          Content ID\n");
  printf(" -l, --np-klicensee     16 bytes              Override klicensee.\n");
  printf(" -g, --np-real-fname    e.g. EBOOT.BIN        Real Filename\n");
  printf(" -j, --np-add-sig       TRUE/FALSE(default)   Whether to add a NP sig. or not.\n");
  printf(" -p, --sys-param-ver    e.g. 00340001         Set sys_process_param SDK version.\n");

  exit(1);
}

static void parse_args(int argc, char *argv[]) {
  int option_index;
  int c;
  
  static const char* short_options = "hki:d:e:vrt:0:1:s:2:m:K:3:4:5:A:6:7:8:9:b:c:f:l:g:j:p:";
  static struct option long_options[] = {
    { "help",             no_argument,       NULL, 'h' },
    { "print-keys",       no_argument,       NULL, 'k' },
    { "print-infos",      required_argument, NULL, 'i' },
    { "decrypt",          required_argument, NULL, 'd' },
    { "encrypt",          required_argument, NULL, 'e' },
    { "verbose",          no_argument,       NULL, 'k' },
    { "raw",              no_argument,       NULL, 'r' },
    { "template",         required_argument, NULL, 't' },
    { "sce-type",         required_argument, NULL, '0' },
    { "compress-data",    required_argument, NULL, '1' },
    { "skip-sections",    required_argument, NULL, 's' },
    { "key-revision",     required_argument, NULL, '2' },
    { "meta-info",        required_argument, NULL, 'm' },
    { "keyset",           required_argument, NULL, 'K' },
    { "self-auth-id",     required_argument, NULL, '3' },
    { "self-vendor-id",   required_argument, NULL, '4' },
    { "self-type",        required_argument, NULL, '5' },
    { "self-app-version", required_argument, NULL, 'A' },
    { "self-fw-version",  required_argument, NULL, '6' },
    { "self-add-shdrs",   required_argument, NULL, '7' },
    { "self-ctrl-flags",  required_argument, NULL, '8' },
    { "self-cap-flags",   required_argument, NULL, '9' },
    { "np-license-type",  required_argument, NULL, 'b' },
    { "np-app-type",      required_argument, NULL, 'c' },
    { "np-content-id",    required_argument, NULL, 'f' },
    { "np-klicensee",     required_argument, NULL, 'l' },
    { "np-real-fname",    required_argument, NULL, 'g' },
    { "np-add-sig",       required_argument, NULL, 'j' },
    { "sys-param-ver",    required_argument, NULL, 'p' },
    { NULL, 0, NULL, 0 }
  };  
  
  while ((c = option_index = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
    switch ( c ) {
    case '?':
    case 'h':
      show_usage();
      break;	  
    case 'v':
      verbose = 1;
      break;
    case 'r':
      raw_output = 1;
      break;
    case 't':
      template_path = optarg;
      break;
    case '0':
      filetype_value = optarg;
      break;
    case '1':
      compress_value = optarg;
      break;
    case 's':
      skip_sections_value = optarg;
      break;
    case '2':
      key_revision_value = optarg;
      break;
    case 'm':
      meta_info_value = optarg;
      break;
    case 'K':
      outputfile_path = optarg;
      break;
    case '3':
      auth_id_value = optarg;
      break;
    case '4':
      vendor_id_value = optarg;
      break;
    case '5':
      selftype_value = optarg;
      break;
    case 'A':
      app_version_value = optarg;
      break;
    case '6':
      fw_version_value = optarg;
      break;
    case '7':
      add_section_headers_value = optarg;
      break;
    case '8':
      self_control_flags_value = optarg;
      break;
    case '9':
      self_capability_flags_value = optarg;
      break;
    case 'b':
      np_license_type_value = optarg;
      break;
    case 'c':
      np_app_type_value = optarg;
      break;
    case 'f':
      np_content_id_value = optarg;
      break;
    case 'l':
      klicensee_value = optarg;
      break;
    case 'g':
      np_realfilename_value = optarg;
      break;
    case 'j':
      np_add_sig_value = optarg;
      break;
    case 'p':
      sys_process_sdk_version_value = optarg;
      break;
    case 'k':
      option_valid = 1;
      cmd_print_keysets = 1;
      return;
    case 'i':
      option_valid = 1;
      cmd_print = 1;
      inputfile_path = optarg;
      return;
    case 'd':
      option_valid = 1;
      cmd_decrypt = 1;
      inputfile_path = optarg;
      goto get_args;
      break;
    case 'e':
      option_valid = 1;
      cmd_encrypt = 1;
      inputfile_path = optarg;
      goto get_args;
      break;
		  
    default:
      abort();
      break;		  
    }
  }
  
 get_args:
  if (cmd_decrypt) {
    if (argc - optind != 1) {
      printf("[*] Error: Decrypt needs an output file!\n");
      show_usage();
    } else {
      outputfile_path = argv[optind];
    }
    return;
  }
  
  if (cmd_encrypt) {
    if (argc - optind != 1) {
      printf("[*] Error: Encrypt needs an input and output file!\n");
      show_usage();
    } else {
      outputfile_path = argv[optind];
    }
    return;
  }
}


int main(int argc, char **argv)
{ 
  char filename[256]; 

  if ( argc <= 1 )
    show_usage();

  parse_args(argc, argv);
  if ( !option_valid )
    show_usage();
	
  show_version();  
  printf("\n");

  get_data_filename(SCE_DATA_KEYS, filename);
  if (load_keysets(filename)) {
    if (verbose)
      printf("[*] Loaded keysets.\n");
  } else {
    if (cmd_print_keysets) {
      printf("[*] Error: Could not load keys.\n");
      return 0;
    }
    printf("[*] Warning: Could not load keys.\n");
  }

  // loader curves
  get_data_filename(SCE_DATA_LDR_CURVES, filename);
  if ( load_ldr_curves(filename) ) {
    if ( verbose )
      printf("[*] Loaded loader curves.\n");
  } else {
    printf("[*] Warning: Could not load loader curves.\n");
  }

  // vsh curves
  get_data_filename(SCE_DATA_VSH_CURVES, filename);
  if ( load_vsh_curves(filename) ) {
    if ( verbose )
      printf("[*] Loaded loader curves.\n");
  } else {
    printf("[*] Warning: Could not load loader curves.\n");
  }

  if (klicensee_value) {
    if ( strlen(klicensee_value) != 32 ) {
      printf("[*] Error: klicensee needs to be 16 bytes.\n");
      return 0;
    }
    klicensee = x_to_u8_buffer(klicensee_value);
  } else {
    get_data_filename(SCE_DATA_KLICS, filename);
    if ( load_klicensees(filename) ) {
      if ( verbose )
        printf("[*] Loaded klicensees.\n");
    } else {
      if ( verbose )
        printf("[*] Warning: Could not load klicenseees.\n");
    }
  }

  if (cmd_print_keysets) {
    printf("[*] Loaded keysets:\n");
    print_keysets(stdout);
  } else if (cmd_print) {
    backend_cmd_print();
  } else if (cmd_decrypt) {
    backend_cmd_decrypt();   
  } else if (cmd_encrypt) {
    backend_cmd_encrypt();
  }
  return 0;
}
