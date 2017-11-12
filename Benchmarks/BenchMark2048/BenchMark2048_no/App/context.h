#ifndef CONTEXT_H
#define CONTEXT_H

#include "tileset.h"

enum side_e {UP = 0, DOWN = 1, RIGHT = 2, LEFT = 3};

struct context_t
{
    struct tileset_t tileset;
	/*the grid which is (0;0) -> (nb_cells_h;nb_cells_w)*/
    int **board;
    SDL_Surface *screen;
    int score,		/*current score*/
        best_score,	/*explicit*/
        nb_cells_w,	/*explicit*/
        nb_cells_h;	/*explicit*/
    SDL_bool has_reached_max;	/*true if MAX_VALUE is reached false atherwise and MAX_VALUE is defined in functions.h*/
};

/**
IN :
	- context is a pointer (non-null) on a context_t which is completed and filled in this function
	- path_tileset is a const path to the tileset
OUT :
	- 0 if failed
	- 1 if succeeded
*/
int load_context(struct context_t *context, const char *path_tielset);

/**
IN :
	- context is the context which is freed
OUT :
	- nothing
*/
void free_context(struct context_t *context);

#endif
