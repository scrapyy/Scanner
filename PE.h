#pragma once
#include<Windows.h>
#include<stdlib.h>
#include<stdio.h>


typedef struct _FORMATPE
{
    HANDLE fileMap;
    DWORD *Base;
    PLARGE_INTEGER size;
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeaders;
    IMAGE_SECTION_HEADER* seHeader;
    IMAGE_EXPORT_DIRECTORY* expHeader;
    IMAGE_IMPORT_DESCRIPTOR* impHeader;
    HANDLE f;
    int Lim;
} FORMATPE;

#define FILE_NOT_FOUND 2
#define PATH_NOT_FOUND 3
#define SIGNATURE 0x5A4D
#define MACHINE_TYPE 0x14c

#define INVALID_IMPORTS 3
#define INVALID_EXPORTS 4
#define INVALID_SECTIONS 5
#define INVALID_DOS 6
#define INVALID_NT 7

int Create(FORMATPE** peFile);
int loadHeaders(FORMATPE* peFile);
void print_NT_headers(FORMATPE* peFile, FILE* f);
void cleanupPEstructure(FORMATPE *peFile);
void PrintDataDirectory(FORMATPE* peFile, FILE* f);
int LoadSectionTable(FORMATPE* peFile);
int LoadExportSimbols(FORMATPE* peFile);
void PrintImportSymbols(FORMATPE* peFile,FILE* f);
int LoadImportSymbols(FORMATPE* peFile);
void print_dos_header(FORMATPE* peFile, FILE* f);
void PrintSectionTable(FORMATPE* peFile, FILE* f);
void PrintExports(FORMATPE* peFile,FILE* f);
BYTE* SearchAddres(FORMATPE* peFile, unsigned int addres, unsigned int size);
int LoadFile(FORMATPE* peFile);