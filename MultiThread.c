#pragma once
#include "MultiThread.h"



void CreateList(LIST_ENTRY *head)
{
    InitializeListHead(head);
}

int CreateNode(NODE** node)
{
    *node = (NODE*)malloc(sizeof(NODE));

    if (*node == NULL)
    {
        return -1;
    }

    return 0;
}

DWORD WINAPI ScanFileThread(Var* param)
{
    while (1)
    {
        int state = WaitForMultipleObjects(2, param->Ev, FALSE, INFINITE);

        state = state - WAIT_OBJECT_0;

        if (state == 1)
        {
            return 0;
        }

        NODE* nod = CONTAINING_RECORD(param->head->Flink, NODE, ListEntry);
        char* path = nod->path;

        EnterCriticalSection(&(param->cs));

        RemoveHeadList(param->head);

        if (param->head != param->head->Flink)
        {
            SetEvent(param->Ev[0]);
        }
        else
        {
            SetEvent(param->empty);
        }

        LeaveCriticalSection(&(param->cs));

        FORMATPE* peFile = NULL;
        int error = 0;
        error = Create(&peFile);

        if (error == -1)
        {
            continue;
        }

        error = OpenEXE(peFile, path);

        if (error != 0)
        {
            continue;
        }


        error = CreateMap(peFile);

        if (error != 0)
        {
            continue;
        }

        FILE* f;

        error = LoadFile(peFile);

        if (error != 0)
        {
            continue;
        }

        EnterCriticalSection(&(param->csf));



        fopen_s(&f, "bla.txt", "a");

        if (f == NULL)
        {
            LeaveCriticalSection(&(param->csf));
            continue;
        }

        fprintf_s(f, "%s\n", path);
        printf("%s\n",path);


        int a = ScanFile(peFile);

        if (a == CLEAN_FILE)
            fprintf_s(f, "Clean file\n");
        else
            fprintf_s(f, "Infected file\n");

        fclose(f);
        LeaveCriticalSection(&(param->csf));

    }
    return 0;
}

void StartThreads(char *path)
{
    HANDLE threads[NUMBER_OF_THREADS];
    LIST_ENTRY head;
    Var param;
    CRITICAL_SECTION cs;
    CRITICAL_SECTION csf;


    InitializeCriticalSection(&cs);
    InitializeCriticalSection(&csf);

    param.Ev[0] = CreateEventA(NULL, FALSE, FALSE, NULL);

    if (param.Ev[0] == NULL)
    {
        return;
    }

    param.head = &head;
    param.Ev[1] = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (param.Ev[0] == NULL)
    {
        return;
    }
    param.cs = cs;
    param.csf = csf;

    param.empty = CreateEventA(NULL, FALSE, FALSE, NULL);

    if (param.empty == NULL)
    {
        return;
    }

    if (param.Ev[0] == NULL)
    {
        return;
    }

    CreateList(&head);

    for (int i = 0; i < NUMBER_OF_THREADS; i++)
    {
        threads[i] = CreateThread(NULL, 0, ScanFileThread, &param, 0, NULL);
    }

    IterateFiles(path, &head, param.Ev[0], param.cs,param.empty);

    WaitForSingleObject(param.empty, INFINITE);

    SetEvent(param.Ev[1]);
    
    for (int i = 0; i < NUMBER_OF_THREADS; i++)
    {
        WaitForSingleObject(threads[i], INFINITE);
    }
    
    
}