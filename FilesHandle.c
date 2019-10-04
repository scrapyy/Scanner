#pragma once
#include "FilesHandle.h"

char* AddWildChar(char* path)
{
    strcat_s(path, strlen(path) + 4, "\\*\0");
    return path;
}
char* RemoveWildChar(char* path)
{
    path[strlen(path) - 2] = 0;
    return path;
}

int ExistFile(char* path)
{
    GetFileAttributesA(path);
    DWORD error = GetLastError();
    if (error == FILE_NOT_FOUND || error == PATH_NOT_FOUND)
    {
        return -1;
    }
    return 0;
}

int IsDirectory(char* path)
{
    int type = GetFileAttributesA(path);

    if (type == FILE_ATTRIBUTE_DIRECTORY)
    {
        return 0;
    }
    return -1;
}

int OpenEXE(FORMATPE* peFile, char *path)
{
    if (ExistFile(path) == 1)
    {
        return -1;
    }

    peFile->f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (peFile == INVALID_HANDLE_VALUE)
    {
        return -1;
    }

    return 0;
}

int CreateMap(FORMATPE* peFile)
{
    peFile->fileMap = CreateFileMappingA(peFile->f, NULL, PAGE_READONLY, 0, 0, "PE_FILE_OBJECT");

    if (peFile->fileMap == NULL)
    {
        return -1;
    }

    peFile->Base = MapViewOfFile(peFile->fileMap, FILE_MAP_READ, 0, 0, 0);

    if (peFile->Base == NULL)
    {
        return -1;
    }

    int error = GetFileSizeEx(peFile->f, peFile->size);

    if (error == 0)
    {
        return -1;
    }

    return 0;
}

char* MakePath(char* path, char* s)
{

    char* res = (char*)malloc(sizeof(char)*(strlen(path) + strlen(s) + 10));



    if (res == NULL)
    {
        return NULL;
    }

    strcpy_s(res, strlen(path) + 1, path);
    res[strlen(path) - 2] = 0;
    strcat_s(res, strlen(res) + 3, "\\");
    strcat_s(res, strlen(s) + 1 + strlen(res), s);


    return res;
}


void IterateFiles(char* path, LIST_ENTRY* head, HANDLE Event, CRITICAL_SECTION cs,HANDLE empty)
{

    if (ExistFile(path) == -1)
    {
        return;
    }
    WIN32_FIND_DATAA* FileData = (WIN32_FIND_DATAA*)malloc(sizeof(WIN32_FIND_DATAA));
    HANDLE headFile;

    path = AddWildChar(path);

    headFile = FindFirstFileA(path, FileData);

    if (headFile == INVALID_HANDLE_VALUE)
    {
        goto end;
    }

    int error = 1;

    do
    {
        char* fpath = MakePath(path, FileData->cFileName);
        if (strcmp(FileData->cFileName, ".") == 0 || strcmp(FileData->cFileName, "..") == 0)
        {
            goto here;
        }

        if (error == -1)
        {
            goto here;
        }

        if (fpath == NULL)
        {
            goto here;
        }

        if (IsDirectory(fpath) == 0)
        {
            IterateFiles(fpath, head, Event, cs,empty);
        }
        else
        {
            NODE* node = NULL;
            int error = CreateNode(&node);


            if (error == -1)
            {
                return;
            }

            node->path = fpath;

            EnterCriticalSection(&cs);
                
            InsertTailList(head, &(node->ListEntry));
            ResetEvent(empty);

            LeaveCriticalSection(&cs);

            SetEvent(Event);

            continue;
        }
    here:
        path = path;
        //free(fpath);
    } while (FindNextFileA(headFile, FileData));
end:
    free(FileData);
}