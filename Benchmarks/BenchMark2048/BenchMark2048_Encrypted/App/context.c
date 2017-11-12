#include "context.h"
#include<stdlib.h>
#include "App.h"
//#include<Windows.h>

int load_context(struct context_t *context, const char *path_context)
{
    int i, j;
    char path_tileset[LEN_MAX];
	
 //LARGE_INTEGER StartingTime, EndingTime, ElapsedMicroseconds;
 //LARGE_INTEGER Frequency;

    FILE *f = fopen(path_context, "r");
    FILE *file_best_score = fopen("data/b_s.bin", "rb");
    fscanf(f, "%d %d", &context->nb_cells_w, &context->nb_cells_h);
    fscanf(f, "%s", path_tileset);
	
	/*board*/
    context->board = malloc(sizeof(*context->board)*context->nb_cells_h);
    for(i = 0; i < context->nb_cells_h; ++i)
        context->board[i] = malloc(sizeof(**context->board)*context->nb_cells_w);
	/*tileset*/

	
//QueryPerformanceFrequency(&Frequency); 
//QueryPerformanceCounter(&StartingTime);


load_tileset(&context->tileset, path_tileset);


/*QueryPerformanceCounter(&EndingTime);
ElapsedMicroseconds.QuadPart = EndingTime.QuadPart - StartingTime.QuadPart;
ElapsedMicroseconds.QuadPart *= 1000000;
ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;*/


 /*   if(load_tileset(&context->tileset, path_tileset) == 0)
        return 0;
*/
    context->has_reached_max = SDL_FALSE;
    context->screen = SDL_SetVideoMode(context->nb_cells_w*context->tileset.tab_pos[0].w,
                                       context->nb_cells_h*context->tileset.tab_pos[0].h,
                                       32,
                                       SDL_HWSURFACE|SDL_DOUBLEBUF);
    if(context->screen == NULL)
    {
        fputs("Unable to create screen\n", stderr);
        free_tileset(&context->tileset);
        return 0;
    }
    /*init board*/
	for(i = 0; i < context->nb_cells_h; ++i)
        for(j = 0; j < context->nb_cells_w; ++j)
            context->board[i][j] = 0;
    context->score = 0;
	/*read best score in file*/
    fread(&context->best_score, sizeof(int), 1, file_best_score);
	/*don't forget to close files and free memory*/
    fclose(file_best_score);
    fclose(f);
    SDL_WM_SetIcon(SDL_LoadBMP("data/icon.bmp"), NULL);
	/*function succeeded thus return 1*/
    return 1;
}

/*explicit enough*/
void free_context(struct context_t *context)
{
    SDL_FreeSurface(context->screen);
    free_tileset(&context->tileset);
}
