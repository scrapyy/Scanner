#pragma once
#include<Windows.h>
#include "list.h"
#include "FilesHandle.h"

typedef struct _NODE
{
    LIST_ENTRY ListEntry;
    char* path;
} NODE;

typedef struct _Var
{
    HANDLE Ev[2];
    LIST_ENTRY* head;
    CRITICAL_SECTION cs;
    CRITICAL_SECTION csf;
    HANDLE empty;
}Var;

void CreateList(LIST_ENTRY* head);
int CreateNode(NODE** node);
void StartThreads(char *path);

#define NUMBER_OF_THREADS 8
