//
// Created by 1 on 27.10.2020.
//

#ifndef DES_HELPERS_H
#define DES_HELPERS_H

bool DEBUG = false;

static const char *optString = "k:p:dh";

static const struct option longOpts[] = {
        {"key", required_argument, NULL, 'k'},
        {"path", required_argument, NULL, 'p'},
        {"debug", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'}
};
int longIndex=0;

#endif //DES_HELPERS_H
