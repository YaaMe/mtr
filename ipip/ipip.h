#pragma once

int ipipdb_init(const char* ipdb);
int ipipdb_destroy();
int ipipdb_find(const uint32_t ip, char *result);
