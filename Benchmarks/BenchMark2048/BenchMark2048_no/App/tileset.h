#ifndef TILESET_H
#define TILESET_H

#include <SDL.h>
#include <SDL_image.h>
#include<stdio.h>

#define LEN_MAX 128
/*comment characters in tileset and context files*/
#define COMMENT_CHAR '#'

struct tileset_t
{
	/*path to the image*/
	char path[LEN_MAX];
	/*surface of the image*/
	SDL_Surface *im;
	/*dimensions of the tileset (in tiles)*/
	int nb_tiles_w,
		nb_tiles_h;
	/*tab with position of each tile on the image*/
	SDL_Rect *tab_pos;
	/*tab with a (1 or 0) value that tells if this tile is submitted to collisions (not used here)*/
	SDL_bool *tab_coll;
};

/**
IN :
	- f is the file that is being read
	- buffer is the string which contains the first non-commented line read
	- buffer_length is used to avoid SEGFAULT errors
OUT :
	- nothing
*/
void get_non_commented_line(FILE *f, char *buffer, int buffer_length);

/**
IN :
	- tileset is the struct which is filled
	- path is the path to the image
OUT :
	- 0 if failed
	- 1 if succeeded
*/
int load_tileset(struct tileset_t *tileset, const char *path);

/**
IN :
	- tileset is the struct which is freed
OUT :
	- nothing
*/
void free_tileset(struct tileset_t *tileset);

/** THE FILE IN path MUST BE A *.tst FILE WITH :
<nb_tiles_w> <nb_tiles_h>
<path> #less than 128 characters in path !
<<boolean value in {0, 1} that tells if collision is needed> if so, a boolean value on each line>

#example for a tileset that has only 1 line with 9 tiles no matter the collisions and has a bmp on tileset.bmp:
9 1
tileset.bmp
0

#another example for a tileset that has 3 lines with 5 tiles each with important collisions management
#and the same path for the image :
3 5
tileset.bmp
1
#this line is ignored because it starts with a '#'
#warning ! a comment cannot be more than 128 characters long otherwise undefined behaviour will happen
#here 15 numbers will be on a different line each to tell whether or not this tile may collide
0
0
0
0
1
1
1
0
1
1
1
0
1
0
1
**/

#endif
