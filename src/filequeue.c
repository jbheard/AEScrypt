#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>   // realpath

#ifdef _WIN32
	#include <windows.h>  // GetFullPathName
#endif

#include "utils.h"
#include "filequeue.h"

static struct PathNode* newPathNode(const char*);
static void freeNode(struct PathNode*);
static struct PathNode* expandDirectory(struct PathNode*, const char*);

static struct PathNode* newPathNode(const char* path) {
	struct PathNode* node = malloc(sizeof(struct PathNode));
	node->path = malloc(strlen(path)+1);
	strcpy(node->path, path);
	node->next = NULL;
	return node;
}

static void freeNode(struct PathNode* node) {
	free(node->path);
	free(node);
}

static struct PathNode* expandDirectory(struct PathNode* node, const char* directory) {
	char buf[PATH_MAX_LENGTH+1] = {0};
	DIR *dir;
	struct dirent *ent;
	if((dir = opendir(node->path)) != NULL) {
		/* print all the files and directories within directory */
		while((ent = readdir (dir)) != NULL) {
#ifdef _WIN32
			GetFullPathName(node->path, PATH_MAX_LENGTH, buf, NULL);
			sprintf(buf, "%s%c%s", buf, kPathSeparator, ent->d_name);
#else
			realpath(node->path, buf);
			sprintf(buf, "%s%c%s", buf, kPathSeparator, ent->d_name);
#endif
			node = pushNextPath(node, buf);
		}
		closedir(dir);
	} else {
		// Could not open directory
		perror("Error");
	}

	return node;
}

struct PathNode* pushNextPath(struct PathNode* node, const char* path) {
	struct PathNode* newNode = newPathNode(path);
	newNode->next = node;
	return newNode;
}

// Returns the next file path, automatically expands directories
struct PathNode* getNextPath(struct PathNode* node, char* path) {
	if(!node) {
		path[0] = '\0';
		return NULL;
	}
	
	strncpy(path, node->path, PATH_MAX_LENGTH-1);
	struct PathNode* nextNode = node->next;
	
	freeNode(node);
	
	if(is_dir(path)) {
		nextNode = expandDirectory(nextNode, path);
		if(nextNode && is_dir(nextNode->path)) {
			return getNextPath(nextNode, path);
		}
	}
	
	return nextNode;
}

