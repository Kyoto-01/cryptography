#include <stdio.h>
#include <string.h>

#define MAX_STR_LEN 100

int main() {

    char message[MAX_STR_LEN];
    char key[MAX_STR_LEN];
    char encrypted[MAX_STR_LEN];
    char decrypted[MAX_STR_LEN];
    char xor;
    int messageLen, i;

    strcpy(message, "Hello World!");
    strcpy(key, "abcdfigjtigk");
    messageLen = strlen(message);

    for (i = 0; i < messageLen; ++i) {
        xor = message[i] ^ key[i];
        encrypted[i] = xor;
    }
    encrypted[i] = '\0';

    for (i = 0; i < messageLen; ++i) {
        xor = encrypted[i] ^ key[i];
        decrypted[i] = xor;
    }
    decrypted[i] = '\0';

    printf("Original text: %s\n", message);
    printf("Generated key: %s\n", key);
    printf("Encrypted text: %s\n", encrypted);
    printf("Decrypted text: %s\n", decrypted);
    
    printf("Test status: ");
    if (strcmp(message, decrypted) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
    }

    return 0;
}