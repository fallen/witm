#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dnet.h>
#include <pcap.h>

#include "witm.h"
#define PLUGIN_FILENAME_MAX_LENGTH 255

struct plugin *plugins = NULL;

int add_plugin(char *name, char *author, void *lib) {
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

	return 1;
}

int load_plugins(void) {

	FILE *fp;
	char plugin_file[] = "plugins";
	int ret;
	char plugin_lib_name[PLUGIN_FILENAME_MAX_LENGTH];
	void *lib_pointer;
	char *plugin_name;
	char *plugin_author;
	int (*startup)(void) = NULL;
	fp = fopen(plugin_file, "r");
	if (fp == NULL) {
		perror("Error opening the plugins file : ");
		return -1;
	}

	while ( !feof(fp) && (fgets(plugin_lib_name, PLUGIN_FILENAME_MAX_LENGTH, fp) != NULL) ) {
		if (plugin_lib_name[strlen(plugin_lib_name) - 1] == '\n')
			plugin_lib_name[strlen(plugin_lib_name) - 1] = '\0';
		printf("\n\tLoading plugin %s\n", plugin_lib_name);
		lib_pointer = dlopen(plugin_lib_name, RTLD_FIRST);
		if (lib_pointer == NULL) {
			printf("\nCannot open the shared object : %s because : %s\n", plugin_lib_name, dlerror());
			return -1;
		}
		plugin_name = dlsym(lib_pointer, "name");
		plugin_author = dlsym(lib_pointer, "author");
		startup = dlsym(lib_pointer, "startup");

		startup(); // We call the startup function of the plugin

		add_plugin(plugin_name, plugin_author, lib_pointer);
	}
	
	fclose(fp);

	return 1;
}

void show_plugins_info(void) {
	struct plugin *tmp;
	for (tmp = plugins ; tmp != NULL ; tmp = tmp->next)
		printf("Plugin %s by %s\n", tmp->name, tmp->author);
}
