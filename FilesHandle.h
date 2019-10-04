#pragma once
#include "PE.h"
#include "Protect.h"
#include "MultiThread.h"

int ExistFile(char* path);
int OpenEXE(FORMATPE* peFile, char *path);
int CreateMap(FORMATPE* peFile);
void IterateFiles(char* path, LIST_ENTRY* head, HANDLE Event,CRITICAL_SECTION cs,HANDLE empty);
char* AddWildChar(char* path);
