#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include "context.h"

#define PROBABILITY_4 10 /*10%*/
#define EMPTY_CELL 0


#define MAX_VALUE i_log2(2048)
#define MAX_VALUE_STRING "2048"

/**
IN :
	- context is used to access the board to blit every tile on screen
OUT :
	- nothing
*/
void blit_all(const struct context_t *context);


/**
IN :
	- context is used to access the board to set a newnon-empty cell
	- value is the new cell value
OUT :
	- nothing
*/
void generate_new_cell(struct context_t *context, int value);

/**
IN :
	- context is used to access the board
OUT :
	- returns the value of the exposant of 2 which is the highest in the board
*/
int get_max_value(const struct context_t *context);

/**
IN :
	- context is used to access the screen surface
OUT :
	- nothing
*/
void ask_for_screenshot(const struct context_t *context);

/**
IN :
	- context is used to access has_reached_max and to be sent to ask_for_screenshot
OUT :
	- SDL_TRUE is returned if and only if player has reached MAX_VALUE and asked to quit
	- SDL_FALSE is returned if :
		* player didn't reach MAX_VALUE
		* player reached MAX_VALUE and asked to continue playing
*/
SDL_bool check_if_max(struct context_t *context);

/**
IN :
	- context is used to accesthe board
OUT :
	- SDL_FALSE if game continues
	- SDL_TRUE otherwise
*/
SDL_bool isover(struct context_t *context);

/**
IN :
	- context is used to access tileset, board, has_reached_max, etc.
OUT :
	- 0 if player quits before game being over
	- 1 if game is over
*/
int play(struct context_t *context);

/**
IN :
	- context is used to acess board
	- x and y are the coordinate of the cell to move
	- vector is the deplacement vector (left, up, right or down)
OUT :
	- 0 if no move has been possible
	- n otherwise such as n is the number of moves
*/
int move_cell(struct context_t *context, int x, int y, int vector[2]);

/**
IN :
	- context is used to acces board mostly
	- side is the direction of the movement
OUT :
	- 0 if no move has been possible
	- n otherwise such as n is the number of moves
*/
int move(struct context_t *context, enum side_e side);

#endif
