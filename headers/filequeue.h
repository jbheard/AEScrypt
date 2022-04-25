#ifndef _FILEQUEUE_H_
#define _FILEQUEUE_H_

#define PATH_MAX_LENGTH 2048

struct PathNode {
	char *path;
	struct PathNode* next;
};

struct PathNode* getNextPath(struct PathNode* node, char* path);
struct PathNode* pushNextPath(struct PathNode* node, const char* path);

#endif // _FILEQUEUE_H_
