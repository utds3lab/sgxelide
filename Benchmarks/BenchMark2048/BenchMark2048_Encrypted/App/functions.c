#include "functions.h"
#include <time.h>
#include "App.h"

#define NEW_CELL_VALUE(n) i_log2(n)

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/*explicit enough*/
void blit_all(const struct context_t *context)
{
    int i, j;
    SDL_Rect dstrect;
    dstrect.h = context->tileset.tab_pos[0].h;
    dstrect.w = context->tileset.tab_pos[0].w;
    for(i = 0; i < context->nb_cells_h; ++i)
    {
        dstrect.y = i*dstrect.h;
        for(j = 0; j < context->nb_cells_w; ++j)
        {
            dstrect.x = j*dstrect.w;
            SDL_BlitSurface(context->tileset.im, &context->tileset.tab_pos[context->board[i][j]], context->screen, &dstrect);
        }
    }
}

/*explicit enough*/
void generate_new_cell(struct context_t *context, int value)
{
    int x, y;
    do
    {
        x = rand()%context->nb_cells_w;
        y = rand()%context->nb_cells_h;
    } while(context->board[y][x] != 0);
    context->board[y][x] = value;
}

/*explicit enough*/
int get_max_value(const struct context_t *context)
{
    int i, j,
        max_value = 0;
    for(i = 0; i < context->nb_cells_h; ++i)
        for(j = 0; j < context->nb_cells_w; ++j)
            if(max_value < context->board[i][j])
                max_value = context->board[i][j];
    return max_value;
}

void ask_for_screenshot(const struct context_t *context)
{
    time_t timestamp = time(NULL);
    char buffer_title[LEN_MAX];
    SDL_Event ev;
    SDL_bool _loop = SDL_TRUE;

    SDL_WM_SetCaption("Press Y if you want to make a screenshot and N if you don't", NULL);
    do
    {
        do
            SDL_WaitEvent(&ev);
        while(ev.type != SDL_KEYDOWN);
        if(ev.key.keysym.sym == SDLK_y)
        {
			/*uses the timestamp to create the title of the new screenshot file*/
            sprintf(buffer_title, "data/z2048 - last screen [%d].bmp", (int)timestamp);
            SDL_SaveBMP(context->screen, buffer_title);
            _loop = SDL_FALSE;
        }
        if(ev.key.keysym.sym == SDLK_n)
            _loop = SDL_FALSE;
    } while(_loop);
}

SDL_bool check_if_max(struct context_t *context)
{
    SDL_Event e;
    SDL_bool _loop = SDL_TRUE,
             ret = SDL_FALSE;
    if(get_max_value(context) == MAX_VALUE && !context->has_reached_max)
    {
        context->has_reached_max = SDL_TRUE;
        SDL_WM_SetCaption("You have reached " MAX_VALUE_STRING ", do you want to continue ? (q) to quit OR (c) to continue",  NULL);
        do
        {
            do
                SDL_WaitEvent(&e);
            while(e.type != SDL_KEYDOWN);
            if(e.key.keysym.sym == SDLK_q)
            {
                ret = SDL_TRUE;
                _loop = SDL_FALSE;
            }
            else if(e.key.keysym.sym == SDLK_c)
            {
                _loop = SDL_FALSE;
                ask_for_screenshot(context);
            }
        }while(_loop);
    }
    return ret;
}

SDL_bool isover(struct context_t *context)
{
    int i, j, k,
		/*vx and vy are the 2 components of a vector which is used to access every adjacent cell (only horizontal and vertical)*/
        vx[4] = {-1,  0,  0, +1,},
        vy[4] = { 0, -1, +1,  0};
	/*if user asked to quit, then game is over*/
    if(check_if_max(context))
        return SDL_TRUE;
	/*for each cell*/
    for(i = 0; i < context->nb_cells_h; ++i)
        for(j = 0; j < context->nb_cells_w; ++j)
			/*if the cell has the biggest value allowed by the tileset*/
            if(context->board[i][j] == (context->tileset.nb_tiles_w*context->tileset.nb_tiles_h)-1)
				/*then game is over*/
                return SDL_TRUE;
	/*for each cell*/
    for(i = 0; i < context->nb_cells_h; ++i)
        for(j = 0; j < context->nb_cells_w; ++j)
			/*if the cell is empty*/
            if(context->board[i][j] == EMPTY_CELL)
				/*then the game isn't over*/
                return SDL_FALSE;
    /*here, each cell is occupied (thus non-empty)*/
	/*for each cell*/
    for(i = 0; i < context->nb_cells_h; ++i)
        for(j = 0; j < context->nb_cells_w; ++j)
            for(k = 0; k < 4; ++k)
                /*If there is still an available move*/
                if((i + vy[k] >= 0 && i + vy[k] < context->nb_cells_w) && (j + vx[k] >= 0 && j + vx[k] < context->nb_cells_h) &&
                            context->board[i+vy[k]][j+vx[k]] == context->board[i][j])
					/*then the game isn't over*/
                    return SDL_FALSE;
	/*otherwise, game is over*/
    return SDL_TRUE;
}

int play(struct context_t *context)
{
	/*changing title is the way used to interact with player*/
    char title[LEN_MAX];
    FILE *file_best_score = fopen("data/b_s.bin", "rb+");
    int best_score_tmp;
    SDL_Event e;
    generate_new_cell(context, rand()%100 < PROBABILITY_4 ? NEW_CELL_VALUE(4) : NEW_CELL_VALUE(2));
	/*the game has to start with at least one busy cell*/
    do
    {
		/*update title with current and best scores*/
        sprintf(title, "SDL_z2048\t : score : %d     best score : %d", context->score, MAX(context->best_score, context->score));
        SDL_WM_SetCaption(title, NULL);
        blit_all(context);
        SDL_Flip(context->screen);
		/*while player didn't press an arrow which represents an available movement, loop*/
        do
        {
			/*ask for an event while user doesn't press an arrow or double clicks on the upper left corner to leave*/
            do
                SDL_WaitEvent(&e);
            while((e.type != SDL_QUIT && e.type != SDL_KEYDOWN) ||
                  (e.key.keysym.sym != SDLK_LEFT && e.key.keysym.sym != SDLK_RIGHT &&
                   e.key.keysym.sym != SDLK_UP && e.key.keysym.sym != SDLK_DOWN && e.key.keysym.sym != SDLK_ESCAPE));
			/*if player tries to leave*/
            if(e.type == SDL_QUIT || e.key.keysym.sym == SDLK_ESCAPE)
				/*then quit the game*/
                return 0;
        } while(move(context, e.key.keysym.sym - SDLK_UP) == 0);
		/*update screen after movement*/
        blit_all(context);
        SDL_Flip(context->screen);
		/*wait 50 miliseconds between each turn to get a bit slower*/
        SDL_Delay(50);
        generate_new_cell(context, rand()%100 < PROBABILITY_4 ? NEW_CELL_VALUE(4) : NEW_CELL_VALUE(2));
		/*the new cell has to be generated just before the board is checked otherwise function may be bugged*/
    } while(!isover(context));
	/*update screen when player wins or looses*/
    blit_all(context);
    SDL_Flip(context->screen);
	
	/*if current score is better than previous recorded best score, then replace it*/
    fread(&best_score_tmp, sizeof(int), 1, file_best_score);
    rewind(file_best_score);
    if(context->score > best_score_tmp)
        fwrite(&context->score, sizeof(int), 1, file_best_score);
	/*do not forget to free memory*/
    fclose(file_best_score);
    return 1;
}

int move_cell(struct context_t *context, int x, int y, int vecteur[2])
{
    int tmp_x = x,
        tmp_y = y;
	/*first find the next non-free cell in that direction starting from (x;y)*/
    do
    {
        tmp_x += vecteur[0];
        tmp_y += vecteur[1];
    } while(tmp_x < context->nb_cells_w && tmp_x >= 0 && tmp_y < context->nb_cells_h && tmp_y >= 0 && context->board[tmp_y][tmp_x] == EMPTY_CELL);
    /*if context->board[tmp_y][tmp_x] is on screen*/
	if(tmp_x < context->nb_cells_w && tmp_x >= 0 && tmp_y < context->nb_cells_h && tmp_y >= 0)
    {	/*and if the new non-empty cell has the same value than the (x;y) cell*/
        if(context->board[tmp_y][tmp_x] == context->board[y][x])
        {
			/*then add those twho cells and update score*/
            ++context->board[tmp_y][tmp_x];
            context->board[y][x] = 0;
            context->score += 2 << (context->board[tmp_y][tmp_x] - 1);
            return 1;
        }
        /*otherwise, if the next non-empty cell isn't right after (x;y) cell*/
		else
        {
			
            if(tmp_y - vecteur[1] != y || tmp_x - vecteur[0] != x)
            {
				/*then move the (x;y) cell*/
                context->board[tmp_y - vecteur[1]][tmp_x - vecteur[0]] = context->board[y][x];
                context->board[y][x] = 0;
                return 1;
            }
        }
    }
	/*otherwise, context->board[tmp_y-1][tmp_x-1] is on the edge*/
	/*if the next non-empty cell isn't right after (x;y) cell*/
    else if(tmp_y - vecteur[1] != y || tmp_x - vecteur[0] != x)
    {
		/*then move the (x;y) cell*/
        context->board[tmp_y - vecteur[1]][tmp_x - vecteur[0]] = context->board[y][x];
        context->board[y][x] = 0;
        return 1;
    }
    return 0;
}

/*UNKNOWN is only used in declaration to be clear*/
#define UNKNOWN 0
int move(struct context_t *context, enum side_e direction)
{
    int n_moves = 0,
        i, j;
		/*is the the different vector deplacement (in order : UP, DOWN, RIGHT, LEFT)*/
    int d[4][2] = {{0, -1}, {0, 1}, {1, 0}, {-1, 0}},
		/*those 3 variables are used in for loops*/
        j_initial[] = {1, UNKNOWN, UNKNOWN, 1},
        j_final[] = {UNKNOWN, -1, -1, UNKNOWN},
        j_iterator[] = {+1, -1, -1, +1};
    j_initial[1] = context->nb_cells_h-2; j_initial[2] = context->nb_cells_w-2;
    j_final[0] = context->nb_cells_h;       j_final[3] = context->nb_cells_w;
	
	/*for each line or column (depending on the direction)*/
    for(i = 0; i < ((direction == LEFT || direction == RIGHT) ? context->nb_cells_h : context->nb_cells_w); ++i)
    {
		/*for every cell of the line or column*/
        for(j = j_initial[direction]; j != j_final[direction]; j += j_iterator[direction])
        {
            int y = (direction == LEFT || direction == RIGHT) ? i : j,
                x = (direction == LEFT || direction == RIGHT) ? j : i;
			/*if the concerned cell isn't empty*/
            if(context->board[y][x] != EMPTY_CELL)
				/*then move the cell*/
                n_moves += move_cell(context, x, y, d[direction]);
        }
    }
    return n_moves;
}

int i_log2(int n)
{
	int i;
	for(i = 0; i < sizeof(n)*8; ++i)
		if((n >> i) & 1)
			return i;
	return -1;
}
