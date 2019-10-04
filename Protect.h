#pragma once

#include<string.h>
#include<stdio.h>
#include "PE.h"

#define CLEAN_FILE 1
#define INFECTED_FILE 0
#define SECTION_NAME ".Adson"
#define SECTION_SIZE 0x617
#define EXE_SIGNATURE 0x5A4D
#define MACHINE_SIGNATURE 0x4550

#define FIRST_HASH 1714362211
#define SECOND_HASH 1597164383




int ScanFile(FORMATPE* peFile);

