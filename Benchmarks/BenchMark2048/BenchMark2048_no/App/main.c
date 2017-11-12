#include <stdlib.h>
#include<stdio.h>
#include <time.h>
#include "context.h"
#include "functions.h"
#include "App.h"

#define PATH_CONTEXT "data/context.ctx"

int main(int ac, char **av)
{
    struct context_t context;
    if(load_context(&context, PATH_CONTEXT) == 0)
    {
        fputs("Unable to load context", stderr);
        return EXIT_FAILURE;
    }
    srand((unsigned int)time(NULL));

    play(&context);
	/*when game is over, player may keep a screenshot of his game*/
    ask_for_screenshot(&context);

	/*then free memory*/
    free_context(&context);
    SDL_Delay(500);
	/*and quit*/
    return EXIT_SUCCESS;
	/*hack to avoid warnings from gcc because of unused variables*/
    (void)ac;
    (void)av;
}

