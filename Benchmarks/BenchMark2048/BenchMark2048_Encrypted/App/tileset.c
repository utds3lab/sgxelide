#include "tileset.h"
#include <string.h>
#include <stdio.h>
#include "App.h"

/*explicit enough*/
void get_non_commented_line(FILE *f, char *buffer, int buffer_length)
{
    char *tmp;
	do
		tmp = fgets(buffer, buffer_length, f);
	while(*buffer == COMMENT_CHAR && tmp != NULL);
	if(strrchr(buffer, '\n') != NULL)
        *strrchr(buffer, '\n') = '\0';
}


int load_tileset(struct tileset_t *tileset, const char *path)
{
	char buffer[LEN_MAX];
	//SDL_Surface	*temp = 0;
	char *fnamemod;
	unsigned char *buf;
	unsigned char *buf2;
	int i, j;
	uint32_t flen;
	uint8_t *ebytes;
	uint8_t *bytes;
	SDL_RWops *rwops;//Used to load imagedata
	SDL_RWops *rwopsTMP;//Used to load imagedata
	
	
	FILE *f = fopen(path, "r");
	FILE *fptr;
	
	if(f == NULL)
		return 0;
    rewind(f);
	/*nb_tiles_x*/
	get_non_commented_line(f, buffer, LEN_MAX);
	sscanf(buffer, "%d %d", &tileset->nb_tiles_w, &tileset->nb_tiles_h);

	/*path and im*/
	get_non_commented_line(f, buffer, LEN_MAX);
	strcpy(tileset->path, buffer);
	
	/*bridge_init_store();
		fptr = fopen(tileset->path,"rb");
		fseek(fptr,0,SEEK_END);
		flen = ftell(fptr);
		rewind(fptr);

		buf = (unsigned char *)malloc((flen)*sizeof(unsigned char));
		fread(buf,flen,1,fptr);
		fclose(fptr);

		bridge_add_to_store(&flen,sizeof(flen));
		bridge_add_to_store(buf,flen);//Dump the entire file into the store
		buf2=(unsigned char *)malloc(flen);
		bridge_get_from_store(buf2,flen,1);
		fnamemod = (char *)malloc(strlen(tileset->path)+5);
		memcpy(fnamemod,tileset->path,strlen(tileset->path));
		memcpy(fnamemod+strlen(tileset->path),".txt\0",5);
		bridge_encrypt_store((const char *)fnamemod);
		*/
	
	init_enclave();
	
	/*
	Modified filename (for encrypted version of images)
	*/
	fnamemod = (char *)malloc(strlen(tileset->path)+5);
	memcpy(fnamemod,tileset->path,strlen(tileset->path));
	memcpy(fnamemod+strlen(tileset->path),".txt\0",5);

	/*
	Retrieve, decrypt, and load image
	*/
	bridge_init_store();
	fptr = fopen(fnamemod,"rb");
	fread(&flen,sizeof(flen),1,fptr);
	ebytes = (uint8_t *)malloc(flen);
	fread(ebytes,sizeof(*ebytes),flen,fptr);
	fclose(fptr);
	bridge_decrypt_store(ebytes, flen);
	bridge_get_from_store((uint8_t *)&flen,sizeof(flen),0);
	bytes = (uint8_t *)malloc(flen);//New value of flen has unencrypted file's length
	bridge_get_from_store(bytes,flen,1);
	bridge_free_store();

	rwops = SDL_RWFromMem(bytes,flen);
	tileset->im = IMG_Load_RW(rwops,1);//1 means it will free rwops for us

	free(fnamemod);
	free(ebytes);
	free(bytes);
	
    if(tileset->im == NULL)
	{
	    fputs("Unable to load tileset image\n", stderr);
		fclose(f);
		return 0;
	}

	/*tab_pos*/
	tileset->tab_pos = malloc(tileset->nb_tiles_w*tileset->nb_tiles_h*sizeof(*tileset->tab_pos));
	if(tileset->tab_pos == NULL)
	{
	    fputs("Unable to malloc tileset->tab_pos\n", stderr);
		fclose(f);
		SDL_FreeSurface(tileset->im);
		return 0;
	}
	for(i = 0; i < tileset->nb_tiles_h; ++i)
	{
		for(j = 0; j < tileset->nb_tiles_w; ++j)
		{
			tileset->tab_pos[tileset->nb_tiles_w*i + j].h = tileset->im->h/tileset->nb_tiles_h;
			tileset->tab_pos[tileset->nb_tiles_w*i + j].w = tileset->im->w/tileset->nb_tiles_w;
			tileset->tab_pos[tileset->nb_tiles_w*i + j].y = i*tileset->im->h/tileset->nb_tiles_h;
			tileset->tab_pos[tileset->nb_tiles_w*i + j].x = j*tileset->im->w/tileset->nb_tiles_w;
		}
	}

	/*tab_coll*/
	get_non_commented_line(f, buffer, LEN_MAX);
	if(*buffer == '0')
		tileset->tab_coll = NULL;
	else
	{
		tileset->tab_coll = malloc(tileset->nb_tiles_w*tileset->nb_tiles_h*sizeof(*tileset->tab_coll));
		if(tileset->tab_coll == NULL)
		{
		    fputs("Unable to malloc tileset->tab_coll\n", stderr);
			fclose(f);
			SDL_FreeSurface(tileset->im);
			free(tileset->tab_pos);
			return 0;
		}
		for(i = 0; i < tileset->nb_tiles_h; ++i)
		{
			for(j = 0; j < tileset->nb_tiles_w; ++i)
			{
				get_non_commented_line(f, buffer, LEN_MAX);
				tileset->tab_coll[tileset->nb_tiles_h*i + j] = *buffer == '1' ? SDL_TRUE : SDL_FALSE;
			}
		}
	}
	return 1;
} 


/*explicit enough*/
void free_tileset(struct tileset_t *tileset)
{
    SDL_FreeSurface(tileset->im);
    free(tileset->tab_pos);
    free(tileset->tab_coll);
}

