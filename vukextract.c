/*
 * File: vukextract.c
 * Author: m4tthi4s
 * Date: 11.03.2017
 *
 * Desc: This program extracts Bluray VUKs from a running DVDFab instance
 * Usage: ./vukextract
 *
 ******************************************************************************
 * (C) Copyright 2017
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 ******************************************************************************
 *
 * TODO:
 * - direct download: http://www.dvdfab.cn/mlink/download.php?g=DVDFAB10
 * - apply linux-kernel coding style
 * - https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html#Getopt-Long-Option-Example
 *
 *
 * - http://git.videolan.org/?p=libaacs.git;a=blob;f=src/examples/aacs_info.c;h=ff78f73061226bbf0119429549fe50571a69c0a6;hb=HEAD
 * - http://git.videolan.org/?p=libaacs.git;a=blob_plain;f=KEYDB.cfg;hb=HEAD
 * - view-source:http://www.labdv.com/aacs/KEYDB.cfg
 *
 * - https://wiki.winehq.org/Useful_Registry_Keys
 *
 *
 *   AACS folder (e.g. D:/AACS if the drive is D) = 0x0000 (base address)
 *   DiscID [20 bytes] = 0x0114 (offset from AACS folder)
 *   VolumeID [16 bytes] = 0x0018 (offset from DiscID) = 0x012C (offset from AACS folder)
 *   MediaKey [16 bytes] = 0x0037 (offset from VolumeID) = 0x0163 (offset from AACS folder)
 *   VUK [16 bytes] = 0x0010 (offset from MediaKey) = 0x0173 (offset from AACS folder)
 *
 * */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/param.h>

#include <regex.h>

#include <gcrypt.h>

#define VERSION "1.0.0"

typedef struct {
  char *dvdfab_bin;
  char *dvdfab_log;
  char *dump;
  char *disc_id;
  char *eject_cmd;
} vukconfig_t;

typedef struct {
  uint8_t disc_id[20];
  uint8_t volume_id[16];
  uint8_t mediakey[16];
  uint8_t vuk[16];
  char *title;
  char *comment;
} aacs_t;

void crypto_aes128d(const uint8_t *key, const uint8_t *data, uint8_t *dst) {
    gcry_cipher_hd_t gcry_h;

    gcry_cipher_open(&gcry_h, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, 0);
    gcry_cipher_setkey(gcry_h, key, 16);
    gcry_cipher_decrypt(gcry_h, dst, 16, data, 16);
    gcry_cipher_close(gcry_h);
}


vukconfig_t* vukconfig_create(int argc, char **argv) {
  vukconfig_t* config = malloc(sizeof(vukconfig_t));
  config->dvdfab_bin = NULL;
  config->dvdfab_log = NULL;
  config->dump = NULL;
  config->disc_id = NULL;
  config->eject_cmd = "eject";

  struct option long_options[] = {
    {"fab", required_argument, 0, 'f'},
    {"log", required_argument, 0, 'l'},
    {"dump", required_argument, 0, 'd'},
    {"disc_id", required_argument, 0, 'i'},
    {"eject_cmd", required_argument, 0, 'e'},
    {0, 0, 0, 0}
  };


  while (1) {
    int option_index = 0;

    int c = getopt_long(argc, argv, "f:d:l:i:e:", long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c) {
      case 'f':
        config->dvdfab_bin = strdup(optarg);
        break;
      case 'l':
        config->dvdfab_log = strdup(optarg);
        break;
      case 'd':
        config->dump = strdup(optarg);
        break;
      case 'i':
        config->disc_id = strdup(optarg);
        break;
      case 'e':
        config->eject_cmd = strdup(optarg);
        break;

      case '?':
        /* getopt_long already printed an error message. */
        break;
      default:
        abort();
    }
  }

  return config;
}

void vukconfig_delete(vukconfig_t *config) {
  free(config);
}

aacs_t* aacs_create() {
  aacs_t *key = malloc(sizeof(aacs_t));
  key->title = "__NONAME__";
  key->comment = "vukextract v" VERSION;

  return key;
}

void aacs_delete(aacs_t *key) {
  free(key);
}

int str2hex(char *str, uint8_t *hex, int len) {
  for (int i = 0; i < len; i++) {
    sscanf(str, "%2hhx", &hex[i]);
    str += 2;
  }

  return 0;
}

char* hex2str(uint8_t *s, unsigned n) {
  const char hex[] = "0123456789ABCDEF";
  char *str = NULL;

  unsigned ii;

  str = malloc(n*2 + 1);
  for (ii = 0; ii < n; ii++) {
      str[2*ii]     = hex[ s[ii] >> 4];
      str[2*ii + 1] = hex[ s[ii] & 0x0f];
  }
  str[2*ii] = 0;

  return str;
}


int print_key(aacs_t *key) {
  char keydb_line[40 + strlen(key->title) + 3*32 + strlen(key->comment) + 35 + 1];

  sprintf(keydb_line, "0x%s = %s | V | 0x%s | M | 0x%s | I | 0x%s ; %s",
      hex2str(key->disc_id, 20), key->title, hex2str(key->vuk, 16),
      hex2str(key->mediakey, 16), hex2str(key->volume_id, 16), key->comment);

  fprintf(stdout, "%s\n", keydb_line);
  fflush(stdout);

  return 0;
}


int search_dump(char *dump, aacs_t *key) {
  fprintf(stderr, "dump file: %s\n", dump);

  FILE *fp = fopen(dump, "r");
  //fseek(fp, 571112100, SEEK_SET);

  uint8_t c;
  int needle = 0;

  while (1) {
    //use fread, faster!
    c = fgetc(fp);
    if (feof(fp))
      break;

    if (c == key->disc_id[needle]) {
      needle++;
      if (needle != 20)
        continue;
      needle = 0;

      fprintf(stderr, "Found: %ld %lx\n", ftell(fp)-20, ftell(fp)-20);

      fseek(fp, 0x0018 - 20, SEEK_CUR);
      for (int i = 0; i < 16; i++) {
        key->volume_id[i] = fgetc(fp);
      }

      fseek(fp, 0x0037 - 16, SEEK_CUR);
      for (int i = 0; i < 16; i++) {
        key->mediakey[i] = fgetc(fp);
      }

      fseek(fp, 0x0010 - 16, SEEK_CUR);
      for (int i = 0; i < 16; i++) {
        key->vuk[i] = fgetc(fp);
      }

      uint8_t vuk_calculated[16];
      crypto_aes128d(key->mediakey, key->volume_id, vuk_calculated);
      for (int i = 0; i < 16; i++) {
        vuk_calculated[i] ^= key->volume_id[i];
      }

      if (memcmp(key->vuk, vuk_calculated, 16) != 0) {
        fprintf(stderr, "VUK invalid.\n");
        needle = 0;
        continue;
      }
      fprintf(stderr, "VUK correct.\n");

      break;
    } else {
      needle = 0;
    }
  }

  fclose(fp);

  return 0;
}


int search_memory(pid_t pid, aacs_t *key, vukconfig_t *config) {
  fprintf(stderr, "Searching memory of: %d\n", pid);

  char fname[16];
  sprintf(fname, "/proc/%d/maps", pid);
  FILE *fp_maps = fopen(fname, "r");
  sprintf(fname, "/proc/%d/mem", pid);
  FILE *fp_mem = fopen(fname, "r");

  unsigned long vm_start, vm_end;
  char rwxs[4];
  unsigned long long pgoff;
  int major, minor;
  unsigned long ino;
  char filename[MAXPATHLEN];

  char *line = NULL;
  size_t len;


  while(getline(&line, &len, fp_maps) > 0) {
    int read = sscanf(line, "%lx-%lx %4s %llx %x:%x %lu %[^\n]", &vm_start,
        &vm_end, rwxs, &pgoff, &major, &minor, &ino, filename);

    if (read == 6)
      filename[0] = '\0';
    if (rwxs[0] != 'r')
      continue;

    //fprintf(stderr, "%lx-%lx %.4s %llx, %x:%x %lu %s\n", vm_start, vm_end, rwxs, pgoff,
    //    major, minor, ino, filename);

    fseek(fp_mem, vm_start, SEEK_SET);

    uint8_t c;
    int needle = 0;
    while (vm_start <= vm_end) {
      c = fgetc(fp_mem);
      vm_start++;

      if (c == key->disc_id[needle]) {
        needle++;
        if (needle != 20)
          continue;
        needle = 0;

        fprintf(stderr, "Found: %ld %lx\n", ftell(fp_mem)-20, ftell(fp_mem)-20);
        fprintf(stderr, "%lx-%lx %.4s %llx, %x:%x %lu %s\n", vm_start, vm_end, rwxs, pgoff,
            major, minor, ino, filename);

        fseek(fp_mem, 0x0018 - 20, SEEK_CUR);
        for (int i = 0; i < 16; i++) {
          key->volume_id[i] = fgetc(fp_mem);
        }

        fseek(fp_mem, 0x0037 - 16, SEEK_CUR);
        for (int i = 0; i < 16; i++) {
          key->mediakey[i] = fgetc(fp_mem);
        }

        fseek(fp_mem, 0x0010 - 16, SEEK_CUR);
        for (int i = 0; i < 16; i++) {
          key->vuk[i] = fgetc(fp_mem);
        }

        uint8_t vuk_calculated[16];
        crypto_aes128d(key->mediakey, key->volume_id, vuk_calculated);
        for (int i = 0; i < 16; i++) {
          vuk_calculated[i] ^= key->volume_id[i];
        }

        if (memcmp(key->vuk, vuk_calculated, 16) != 0) {
          fprintf(stderr, "VUK invalid.\n");
          needle = 0;
          continue;
        }
        fprintf(stderr, "VUK correct.\n");

        system(config->eject_cmd);

        goto found_key;
      } else {
        needle = 0;
      }
    }
  }

found_key:

  fclose(fp_maps);
  fclose(fp_mem);
  free(line);
  return 0;
}

pid_t start_dvdfab(vukconfig_t *config) {
  pid_t pid;

  if ((pid = fork()) == -1) {
    fprintf(stderr, "Fork failed.\n");
  }

  if (pid == 0) {
    fprintf(stderr, "dvdfab_bin: %s\n", config->dvdfab_bin);

    char *args[] = {"bash", "-c", config->dvdfab_bin, NULL};
    //char *args[] = {NULL};
    char **env = calloc(3, sizeof(char*));

    asprintf(&env[0], "DISPLAY=%s", getenv("DISPLAY"));
    asprintf(&env[1], "HOME=%s", getenv("HOME"));
    env[2] = NULL;

    fprintf(stderr, "Starting DVDFab\n");

    int fd = open("/dev/null", O_WRONLY);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);

    execve("/bin/bash", args, env);
    //execve(config->dvdfab_bin, args, env);

    fprintf(stderr, "DVDFab stopped\n");
    exit(-1);
  }

  return pid;
}

int watch_log(char *logfile, aacs_t *key) {
  fprintf(stderr, "Watching logfile: %s\n", logfile);
  FILE *fp = fopen(logfile, "r");

  fseek(fp, 0, SEEK_END);

  char *line = NULL;
  size_t len;

  regex_t regex_vuk;
  regcomp(&regex_vuk, "got vuk", REG_EXTENDED|REG_NEWLINE);
  regex_t regex_disc_id;
  regcomp(&regex_disc_id, "blu-ray ([0-9A-F])", REG_EXTENDED|REG_NEWLINE);
  regex_t regex_title;
  regcomp(&regex_title, "volume label ([^\r]*)", REG_EXTENDED|REG_NEWLINE);

  int nomatch;
  regmatch_t match[2];

  int title_updated = 0;

  while (1) {
    int r = getline(&line, &len, fp);

    if (r == -1) {
      sleep(1);
      continue;
    }

    //fprintf(stderr, "Read: %s", line);

    nomatch = regexec(&regex_vuk, line, 2, match, 0);
    if (!nomatch) {
      fprintf(stderr, "FOUND VUK\n");
      break;
    }

    nomatch = regexec(&regex_disc_id, line, 2, match, 0);
    if (!nomatch) {
      char *pos = line + match[1].rm_so;
      for (int i = 0; i < 20; i++) {
        sscanf(pos, "%2hhx", &(key->disc_id[i]));
        pos+=2;
      }
      fprintf(stderr, "FOUND Discid: %s\n", hex2str(key->disc_id, 20));
      continue;
    }

    nomatch = regexec(&regex_title, line, 2, match, 0);
    if (!nomatch && !title_updated) {
      int len = match[1].rm_eo - match[1].rm_so;
      key->title = malloc(sizeof(char) * (len + 1));

      char *pos = line + match[1].rm_so;
      memcpy(key->title, pos, len);
      key->title[len] = '\0';
      title_updated = 1;

      fprintf(stderr, "FOUND title!: %s\n", key->title);
      continue;
    }
  }

  free(line);
  regfree(&regex_vuk);
  regfree(&regex_disc_id);
  regfree(&regex_title);

  return 0;
}

int main(int argc, char **argv) {
  vukconfig_t* config = vukconfig_create(argc, argv);
  aacs_t *key = aacs_create();

  if (config->dvdfab_bin && config->dvdfab_log) {
    pid_t pid = start_dvdfab(config);
    fprintf(stderr, "PID: %d\n", pid);

    while (1) {
      watch_log(config->dvdfab_log, key);
      //print_key(key);

      search_memory(pid, key, config);
      print_key(key);
    }
  }


  if (config->dump && config->disc_id) {
    str2hex(config->disc_id, key->disc_id, 20);

    search_dump(config->dump, key);

    print_key(key);
  }

  vukconfig_delete(config);
  aacs_delete(key);

  return 0;
}
