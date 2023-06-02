#include <stdio.h>
#include <string.h>
#include "anti_debug.h"

extern char* __executable_start;

// void __attribute__((constructor)) before_main()
// {
//   dbg_checker();
// }

char* calc_addr(char* p_addr)
{
    return p_addr + (unsigned long)&__executable_start;
}

char* undo_xor_string(char* string, int length, char* key, int key_length)
{
    for (int i = 0; i < length; i++)
    {
        string[i] = string[i] ^ key[i % key_length];
    }

    return string;
}

int check_password(const char* p_password) // "MagnuB33r"
{
  char magnupass[10] = {0x39, 0xbe, 0xaf, 0xc3, 0x98, 0xd9, 0x27, 0xf0, 0xc4, 0};
  char key_pass[10] = {0x74, 0xdf, 0xc8, 0xad, 0xed, 0x9b, 0x14, 0xc3, 0xb6, 0};

  return memcmp(undo_xor_string(magnupass, 10, key_pass, 10), p_password, 10) != 0;
}

int __attribute__((optimize("O1"))) main (int argc, char** argv) {
    bool (*indirect_call)(const char*) = NULL;
    char* label_address = 0;

    asm volatile(
    "mov_ins:\n"
    "mov $2283, %%rax\n"
    "xor %%rax, %%rax\n"
    "jz mov_ins+3\n"
    ".byte 0xe8\n"
    : :
    : "%rax");

    asm volatile(
      "xor %%rax, %%rax\n"
      "jz always_here + 1\n"
      "always_here:\n"
      ".byte 0xe8\n"
      : :
      : "%rax");

    indirect_call = check_password - 0x100;

    if (argc != 2) {
        printf("Need exactly one argument.\n");
        return -1;
    }

    label_address = calc_addr(((char*)&&return_here) - (unsigned long)&__executable_start);

    asm volatile(
    "push %0\n"
    "ret\n"
    ".string \"\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\""
    :
    : "g"(label_address));

    indirect_call = indirect_call + 0x100;

    return_here:
    if ((*indirect_call)(argv[1])) {
        printf("No, %s is not correct.\n", argv[1]);
        return 1;
    } else {
        printf("Yes, %s is correct!\n", argv[1]);
    }
    return 0;
}