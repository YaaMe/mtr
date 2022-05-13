#include "config.h"
#include "mtr.h"
#include "../ipip/ipip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

const char *ipip_get_location(struct mtr_ctl *ctl, const char *ip) {
    // result buffer
    static char buf[256];
    buf[0] = '\0';

    // init ipdb reader
    char * defaultDB = "/usr/local/share/17monipdb.ipdb";
    ipdb_reader *reader;
    int err = ipdb_reader_new(defaultDB, &reader);
    if (err) {
        // fail to init db, return empty
        return buf;
    }

    const char *lang[2];
    lang[0] = "CN";
    lang[1] = "EN";

    strcpy(buf, "[");
    ipipdb_find(reader, ip, lang[0], buf + 1);
//    ipipdb_find(res_ip, buf + 1);
    strcat(buf, "]");
    return buf;
}