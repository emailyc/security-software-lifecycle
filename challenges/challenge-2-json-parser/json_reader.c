#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yajl/yajl_tree.h"
#include <afl-fuzz.h>

#ifndef __AFL_FUZZ_TESTCASE_LEN
  ssize_t fuzz_len;
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  unsigned char fuzz_buf[1024000];
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE 1024000

// Function to recursively traverse the JSON tree
void traverse_json(yajl_val node) {
    if (YAJL_IS_OBJECT(node)) {
        for (size_t i = 0; i < node->u.object.len; i++) {
            const char *key = node->u.object.keys[i];
            yajl_val value = node->u.object.values[i];

            const char *path[] = { key, (const char *)0 };
            yajl_val v = yajl_tree_get(node, path, yajl_t_any);

            traverse_json(value);
        }
    } else if (YAJL_IS_ARRAY(node)) {
        for (size_t i = 0; i < node->u.array.len; i++) {
            yajl_val value = node->u.array.values[i];

            traverse_json(value);
        }
    }
    // Add handling for other types if needed
}

int main(void) {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    char errbuf[1024];
    unsigned char *buf = NULL;

    unsigned char *input = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        // if (len >= MAX_INPUT_SIZE) {
        //     continue;  // Skip overly large inputs
        // }

        buf = realloc(buf, len + 1);  // +1 for null terminator
        if (!buf) {
            perror("Failed to allocate buffer");
            exit(EXIT_FAILURE);
        }

        memcpy(buf, input, len);
        buf[len] = '\0';

        yajl_val root = yajl_tree_parse((const char *)buf, errbuf, sizeof(errbuf));
        if (root != NULL) {
            // Traverse the parsed JSON tree
            traverse_json(root);
            yajl_tree_free(root);
        } else {
            printf("Error asing json.\n");
        }
    }
    free(buf);
    return 0;
}

