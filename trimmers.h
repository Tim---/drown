#ifndef TRIMMERS_H
#define TRIMMERS_H

typedef struct
{
    int u;
    int t;
} couple_t;

typedef struct
{
    couple_t *couples;
    size_t n;
} trimmers_t;

typedef int (*oracle_fun)(char *data, void *params);


void trimmers_new(trimmers_t * trimmers, int n);
void trimmers_free(trimmers_t * trimmers);
int find_trimmer(drown_ctx *dctx, trimmers_t *trimmers);


#endif
