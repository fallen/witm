#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "witm.h"
#define PLUGIN_FILENAME_MAX_LENGTH 255

struct plugin *plugins = NULL;

int add_plugin(char *name, char *author, void *lib, int (*do_match)(const u_char *, size_t), void (*process_packet)(u_char *, size_t)) {
	struct plugin *tmp;
	struct plugin *new_plugin = malloc(sizeof(struct plugin));

	if (new_plugin  == NULL) {
		perror("Error allocating memory");
		return -1;
	}

	for (tmp = plugins ; (tmp != NULL) && (tmp->next != NULL); tmp = tmp->next);
	
	if (tmp == NULL)
		plugins = new_plugin;
	else
		tmp->next = new_plugin;

	new_plugin->name = malloc(strlen(name)*sizeof(char));

	if (new_plugin->name == NULL) {
		perror("Error allocating memory");
		return -1;
	}

	strcpy(new_plugin->name, name);
	new_plugin->author = malloc(strlen(author)*sizeof(char));

	if (new_plugin->author == NULL) {
		perror("Error allocating memory");
		return -1;
	}

	strcpy(new_plugin->author, author);
	new_plugin->lib = lib;
	new_plugin->next = NULL;

  new_plugin->do_match = do_match;
  new_plugin->process_packet = process_packet;

	return 1;
}

int load_plugins(void) {

	FILE *fp;
	char plugin_file[] = "plugins.conf";
	char plugin_lib_name[PLUGIN_FILENAME_MAX_LENGTH];
	void *lib_pointer;
	char *plugin_name;
	char *plugin_author;
	int (*startup)(void) = NULL;
  int (*do_match)(const u_char *packet, size_t size);
  void (*process_packet)(u_char *, size_t);

	fp = fopen(plugin_file, "r");
	if (fp == NULL) {
		perror("Error opening the plugins file : ");
		return -1;
	}

	while ( !feof(fp) && (fgets(plugin_lib_name, PLUGIN_FILENAME_MAX_LENGTH, fp) != NULL) ) {
    size_t plugin_lib_name_size = strlen(plugin_lib_name);
		if (plugin_lib_name[plugin_lib_name_size - 1] == '\n')
			plugin_lib_name[plugin_lib_name_size - 1] = '\0';
		printf("\n\tLoading plugin %s\n", plugin_lib_name);
		lib_pointer = dlopen(plugin_lib_name, RTLD_LOCAL);
		if (lib_pointer == NULL) {
			printf("\nCannot open the shared object : %s because : %s\n", plugin_lib_name, dlerror());
			return -1;
		}
		plugin_name = dlsym(lib_pointer, "name");
    if (plugin_name == NULL)
    {
      printf("Error looking up name of the plugin\n");
      exit(1);
    }

		plugin_author = dlsym(lib_pointer, "author");
    if (plugin_author == NULL)
    {
      printf("Error looking up plugin_author of the plugin\n");
      exit(1);
    }
  
		startup = dlsym(lib_pointer, "startup");
    if (startup == NULL)
    {
      printf("Error looking up startup of the plugin\n");
      exit(1);
    }
  
    do_match = dlsym(lib_pointer, "do_match");
    if (do_match == NULL)
    {
      printf("Error looking up do_match of the plugin\n");
      exit(1);
    }
  
    process_packet = dlsym(lib_pointer, "process_packet");
    if (process_packet == NULL)
    {
      printf("Error looking up process_packet of the plugin\n");
      exit(1);
    }
  

		startup(); // We call the startup function of the plugin

		add_plugin(plugin_name, plugin_author, lib_pointer, do_match, process_packet);
	}
	
	fclose(fp);

	return 1;
}

void show_plugins_info(void) {
	struct plugin *tmp;
	for (tmp = plugins ; tmp != NULL ; tmp = tmp->next)
		printf("Plugin %s by %s\n", tmp->name, tmp->author);
}
