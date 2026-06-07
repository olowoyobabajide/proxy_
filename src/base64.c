#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const char *user, const char *pass) {
    if (!user || !pass) return NULL;

    size_t user_len = strlen(user);
    size_t pass_len = strlen(pass);
    
    size_t input_len = user_len + pass_len + 1; 
    char *input = malloc(input_len + 1);
    if (!input) return NULL;
    snprintf(input, input_len + 1, "%s:%s", user, pass);
    
    size_t output_len = 4 * ((input_len + 2) / 3);
    char *output = malloc(output_len + 1);
    if (!output) {
        free(input);
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < input_len; ) {
        uint32_t octet_a = (unsigned char)input[i++];
        uint32_t octet_b = (i < input_len) ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = (i < input_len) ? (unsigned char)input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = (i > input_len + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        output[j++] = (i > input_len) ? '=' : base64_table[triple & 0x3F];
    }
    
    output[output_len] = '\0';
    free(input);
    return output;
}
