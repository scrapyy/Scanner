#pragma once
#include<Windows.h>
#include<stdio.h>
#include "PE.h"
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#include "Protect.h"
#include"FilesHandle.h"
#include "MultiThread.h"



int main(int argc, char **argv)
{
    char* s;
    s = (char*)malloc(sizeof(char) * strlen(argv[1]));
    StartThreads(s);



    //cleanup:
    _CrtDumpMemoryLeaks();
    return 0;
}