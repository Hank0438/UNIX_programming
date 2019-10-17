#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>

int main() {
    regex_t preg;
    regmatch_t pmatch[10];
    size_t nmatch = 10;
    int cflags = REG_EXTENDED | REG_ICASE;
    int i, len, rc;
    char buf[1024], reg[256], str[256];

    while(1) {
        printf("Input exp: ");
        fgets(reg, 256, stdin);
        if(reg[0] == '\n') break;
        strtok(reg,"\n");

        printf("Input str: ");
        fgets(str,256,stdin);
        if(str[0] == '\n') break;
        strtok(str,"\n");

        if( regcomp(&preg, reg, cflags) != 0 ) {
            puts("regex compile error!\n");
            return 1;
        }

        rc = regexec(&preg, str, nmatch, pmatch, 0);
        regfree(&preg);

        if (rc != 0) {
            printf("no match\n");
            continue;
        }

        for (i = 0; i < nmatch && pmatch[i].rm_so >= 0; ++i) {
            len = pmatch[i].rm_eo - pmatch[i].rm_so;
            strncpy(buf, str + pmatch[i].rm_so, len);
            buf[len] = '\0';
            printf("sub pattern %d is %s\n", i, buf);
        }
    }

    return 0;
}
