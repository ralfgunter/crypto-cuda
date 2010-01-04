#include <stdio.h>
#include <stdlib.h>

int loadFileIntoMemory( char **memory, const char *filename ) {
	size_t file_size;
	char pad;
	int i;
	
	// Opens the file
	FILE *fp = fopen(filename, "rb");
	
	// Makes sure the file was really opened
	if (fp == NULL) {
		*memory = NULL;
		return -1;
	}
	
	// Determines file size
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	
	// Returns file pointer to the beginning
	fseek(fp, 0, SEEK_SET);
	
	// Calculates padding
	pad = (-file_size) % 16;
	file_size += pad;
	
	// Allocates memory
	*memory = (char *) malloc(file_size + 1);
	
	// Loads file into memory, making sure the copy's size is the same as the original's
	if (file_size - pad != fread(*memory, sizeof(char), file_size, fp)) {
		free(*memory);
		return -2;
	}
	
	// Closes the file handler (?)
	fclose(fp);
	
	// Pads the message
	for (i = 0; i < pad; ++i) {
		(*memory)[file_size - pad + i] = pad;
	}
	
	// O que raios é que isso faz?
	(*memory)[file_size] = 0;
	
	return file_size;
}

int writeToFile( char *memory, const char *filename, size_t file_size ) {
	FILE *file = fopen(filename, "wb");
	char possible_pad = memory[file_size - 1];
	char counter = 0;
	
	while (memory[file_size - counter - 1] == possible_pad)
		counter++;
	
	if (counter == possible_pad)
		file_size -= possible_pad;
	
	fwrite(memory, sizeof(char), file_size, file);
	fclose(file);
	return 0;
}
