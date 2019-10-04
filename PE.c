#pragma once
#include "PE.h"

BYTE* Add_2_offset(BYTE* addres, long long ct)
{
    addres += ct;
    return addres;
}

BYTE* SearchAddres(FORMATPE* peFile, unsigned int addres, unsigned int size)
{
    IMAGE_SECTION_HEADER* p = peFile->seHeader;
    for (int i = 0; i < peFile->ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (p[i].VirtualAddress <= addres && p[i].VirtualAddress + p[i].Misc.VirtualSize > addres)
        {
            if (p[i].Misc.VirtualSize - addres < size)
            {
                return NULL;
            }
            unsigned int offset = addres - p[i].VirtualAddress;

            if (offset >= p[i].SizeOfRawData)
            {
                return NULL;
            }

            return Add_2_offset((BYTE*)peFile->Base, addres - p[i].VirtualAddress + p[i].PointerToRawData);

        }
    }
    return NULL;
}



int CheckOffset(FORMATPE* peFile, BYTE* offset)
{
    if (offset == NULL)
    {
        return -1;
    }
    if (offset > Add_2_offset((BYTE*)peFile->Base, peFile->size->QuadPart))
    {
        return -1;
    }
    return 0;
}

int cond(IMAGE_THUNK_DATA* img, IMAGE_THUNK_DATA* imgs)
{
    if (img == NULL && imgs == NULL)
        return 0;
    if (img != NULL)
    {
        if (img->u1.AddressOfData == 0)
            return 0;
    }
    else
    {
        if (imgs->u1.AddressOfData == 0)
            return 0;
    }
    return 1;
}

void print_rva_fa(char* s, int rva, FORMATPE* peFile,FILE* f)
{
    fprintf_s(f,s, rva, SearchAddres(peFile, rva, 0));
}



int Create(FORMATPE** peFile)
{
    *peFile = (FORMATPE*)malloc(sizeof(FORMATPE));

    if (*peFile == NULL)
    {
        return -1;
    }

    (*peFile)->size = (PLARGE_INTEGER)malloc(sizeof(LARGE_INTEGER));

    if ((*peFile)->size == NULL)
    {
        return -1;
    }
    (*peFile)->f = NULL;
    (*peFile)->Base = NULL;
    (*peFile)->dosHeader = NULL;
    (*peFile)->expHeader = NULL;
    (*peFile)->fileMap = NULL;
    (*peFile)->impHeader = NULL;
    (*peFile)->ntHeaders = NULL;
    (*peFile)->seHeader = NULL;

    return 0;
}



int loadDosHeader(FORMATPE* peFile)
{
    peFile->dosHeader = (IMAGE_DOS_HEADER*)peFile->Base;

    if (peFile->dosHeader == NULL)
    {
        return INVALID_DOS;
    }

    if (peFile->dosHeader->e_magic != SIGNATURE)
    {
        return INVALID_DOS;
    }

    if (CheckOffset(peFile, (BYTE*)peFile->dosHeader) == -1)
    {
        return INVALID_DOS;
    }

    return 0;
}

int loadNTHeaders(FORMATPE* peFile)
{
    peFile->ntHeaders = (IMAGE_NT_HEADERS*)((DWORD)peFile->dosHeader + (DWORD)peFile->dosHeader->e_lfanew);

    if (peFile->ntHeaders == NULL)
    {
        return INVALID_NT;
    }

    if (CheckOffset(peFile, (BYTE*)peFile->ntHeaders) == -1)
    {
        return INVALID_NT;
    }

    if (peFile->ntHeaders->FileHeader.Machine != MACHINE_TYPE)
    {
        return INVALID_NT;
    }

    if (peFile->ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return INVALID_NT;
    }

    return 0;
}

int loadHeaders(FORMATPE* peFile)
{
    int error = loadDosHeader(peFile);

    if (error != 0)
    {
        return error;
    }

    error = loadNTHeaders(peFile);

    return error;
}

void cleanupPEstructure(FORMATPE *peFile)
{
    if (peFile != NULL)
    {
        UnmapViewOfFile(peFile->dosHeader);
        CloseHandle(peFile->fileMap);
        if (peFile->f != NULL)
            CloseHandle(peFile->f);
        free(peFile->size);
        free(peFile);
    }
}

void print(char *s, int x,FILE* f)
{
    fprintf_s(f,"%s : %x\n", s, x);
}

void PrintDataDirectory(FORMATPE* peFile,FILE* f)
{
    int ct = (BYTE*)peFile->ntHeaders->OptionalHeader.DataDirectory - (BYTE*)&peFile->ntHeaders->OptionalHeader.Magic;
    int lim = (peFile->ntHeaders->FileHeader.SizeOfOptionalHeader - ct) / sizeof(IMAGE_DATA_DIRECTORY);
    peFile->Lim = lim;
    for (int i = 0; i < lim; i++)
    {
        fprintf_s(f,"DataDirectory[%d]: ", i);
        if (peFile->ntHeaders->OptionalHeader.DataDirectory[i].Size == 0)
        {
            fprintf_s(f,"neinitializat\n");
        }
        else
        {
            if (i != 4)
            {
                print_rva_fa("VirtualAddres: RVA:0x%X FA:0x%X", peFile->ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress, peFile,f);
            }
            else
            {
                fprintf_s(f,"VirtualAddres: FA:0x%x", peFile->ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress);
            }

            fprintf_s(f," Size: %d\n", peFile->ntHeaders->OptionalHeader.DataDirectory[i].Size);
        }
    }
    fprintf_s(f,"\n");
}

int LoadSectionTable(FORMATPE* peFile)
{
    peFile->seHeader = (IMAGE_SECTION_HEADER*)Add_2_offset((BYTE*)peFile->ntHeaders, sizeof(IMAGE_FILE_HEADER) + sizeof(int) + peFile->ntHeaders->FileHeader.SizeOfOptionalHeader);

    if (peFile->seHeader == NULL)
    {
        return INVALID_SECTIONS;
    }

    if (CheckOffset(peFile, (BYTE*)peFile->seHeader) == -1)
    {
        return INVALID_SECTIONS;
    }

    IMAGE_SECTION_HEADER* p = peFile->seHeader;

    for (int i = 0; i < peFile->ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (CheckOffset(peFile, (BYTE*)(p)) == -1)
        {
            return INVALID_SECTIONS;
        }
        p++;
    }

    return 0;
}

void PrintSectionTable(FORMATPE* peFile,FILE* f)
{

    IMAGE_SECTION_HEADER* p = peFile->seHeader;

    for (int i = 0; i < peFile->ntHeaders->FileHeader.NumberOfSections; i++)
    {
        fprintf_s(f,"SectionTable[%x]: PointerToRawData: %x SizeOfRawData: %x VirtualAddress: %x VirtualSize: %x\n", i, p[i].PointerToRawData, p[i].SizeOfRawData, p[i].VirtualAddress, p[i].Misc.VirtualSize);
    }
    fprintf_s(f,"\n");
}

int LoadExportSimbols(FORMATPE* peFile)
{
    if (peFile->Lim < 1)
    {
        return -1;
    }

    peFile->expHeader = (IMAGE_EXPORT_DIRECTORY*)SearchAddres(peFile, peFile->ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY));

    if (peFile->ntHeaders->OptionalHeader.DataDirectory[0].Size == 0)
    {
        return -1;
    }

    if (peFile->expHeader == NULL)
    {
        return -1;
    }

    if (CheckOffset(peFile, (BYTE*)peFile->expHeader) == -1)
    {
        return INVALID_EXPORTS;
    }

    DWORD* name = (DWORD*)SearchAddres(peFile, peFile->expHeader->AddressOfNames, peFile->expHeader->NumberOfNames * sizeof(void*));
    WORD* ord = (WORD*)SearchAddres(peFile, peFile->expHeader->AddressOfNameOrdinals, peFile->expHeader->AddressOfFunctions * sizeof(int));
    DWORD* func = (DWORD*)SearchAddres(peFile, peFile->expHeader->AddressOfFunctions, peFile->expHeader->AddressOfFunctions * sizeof(void*));

    if (CheckOffset(peFile, (BYTE*)name) == -1)
    {
        return INVALID_EXPORTS;
    }

    if (CheckOffset(peFile, (BYTE*)ord) == -1)
    {
        return INVALID_EXPORTS;
    }

    if (CheckOffset(peFile, (BYTE*)func) == -1)
    {
        return INVALID_EXPORTS;
    }

    return 0;
}

void PrintExports(FORMATPE* peFile,FILE* f)
{
    DWORD* name = (DWORD*)SearchAddres(peFile, peFile->expHeader->AddressOfNames, peFile->expHeader->NumberOfNames * sizeof(void*));
    WORD* ord = (WORD*)SearchAddres(peFile, peFile->expHeader->AddressOfNameOrdinals, peFile->expHeader->AddressOfFunctions * sizeof(int));
    DWORD* func = (DWORD*)SearchAddres(peFile, peFile->expHeader->AddressOfFunctions, peFile->expHeader->AddressOfFunctions * sizeof(void*));

    for (unsigned int i = 0; i < peFile->expHeader->NumberOfFunctions; i++)
    {
        char* s;

        if (ord[i] < 0 || ord[i] > peFile->expHeader->NumberOfFunctions)
            continue;

        if (i < peFile->expHeader->NumberOfNames)
        {
            s = (char*)SearchAddres(peFile, name[i], sizeof(char));

            if (s == NULL)
                return;
        }
        else s = 0;

        fprintf_s(f,"EXPORT Name:%s Ordinal:%d RVA:0x%X FA:0x%X\n", s, ord[i], func[ord[i]], (int)SearchAddres(peFile, func[ord[i]], sizeof(void*)));
    }
    fprintf_s(f,"\n");
}

int LoadImportSymbols(FORMATPE* peFile)
{
    if (peFile->Lim < 2)
    {
        return -1;
    }

    peFile->impHeader = (IMAGE_IMPORT_DESCRIPTOR*)SearchAddres(peFile, peFile->ntHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    if (peFile->impHeader == NULL)
    {
        return -1;
    }

    if (peFile->ntHeaders->OptionalHeader.DataDirectory[1].Size == 0)
    {
        return -1;
    }

    if (CheckOffset(peFile, (BYTE*)peFile->impHeader) == -1)
    {
        return INVALID_IMPORTS;
    }


    for (int i = 0; peFile->impHeader[i].Name; i++)
    {
        IMAGE_THUNK_DATA* img = (IMAGE_THUNK_DATA*)SearchAddres(peFile, peFile->impHeader[i].OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));

        if (CheckOffset(peFile, (BYTE*)img) == -1)
        {
            return INVALID_IMPORTS;
        }

        IMAGE_THUNK_DATA* imgs = (IMAGE_THUNK_DATA*)SearchAddres(peFile, peFile->impHeader[i].FirstThunk, sizeof(IMAGE_THUNK_DATA));

        if (CheckOffset(peFile, (BYTE*)imgs) == -1)
        {
            return INVALID_IMPORTS;
        }

        while (cond(img, imgs))
        {

            if (img == NULL)
            {
                imgs += 1;
                continue;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(img->u1.Ordinal))
            {
                char* s = (char*)SearchAddres(peFile, peFile->impHeader[i].Name, sizeof(char));

                if (CheckOffset(peFile, (BYTE*)s) == -1)
                {
                    return INVALID_IMPORTS;
                }
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* s = (IMAGE_IMPORT_BY_NAME*)SearchAddres(peFile, img->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME));

                if (CheckOffset(peFile, (BYTE*)s) == -1)
                {
                    return INVALID_IMPORTS;
                }

                char* p = (char*)SearchAddres(peFile, peFile->impHeader[i].Name, sizeof(char));

                if (CheckOffset(peFile, (BYTE*)p) == -1)
                {
                    return INVALID_IMPORTS;
                }
            }
            img += 1;
            imgs += 1;
        }
    }

    return 0;
}

void PrintImportSymbols(FORMATPE* peFile,FILE* f)
{
    for (int i = 0; peFile->impHeader[i].Name; i++)
    {
        IMAGE_THUNK_DATA* img = (IMAGE_THUNK_DATA*)SearchAddres(peFile, peFile->impHeader[i].OriginalFirstThunk, sizeof(IMAGE_THUNK_DATA));

        IMAGE_THUNK_DATA* imgs = (IMAGE_THUNK_DATA*)SearchAddres(peFile, peFile->impHeader[i].FirstThunk, sizeof(IMAGE_THUNK_DATA));

        while (cond(img, imgs))
        {

            if (img == NULL)
            {
                imgs += 1;
                continue;
            }

            if (IMAGE_SNAP_BY_ORDINAL32(img->u1.Ordinal))
            {
                char* s = (char*)SearchAddres(peFile, peFile->impHeader[i].Name, sizeof(char));

                fprintf_s(f,"IMPORT Dll:%s Ordinal:%x\n", s, img->u1.Ordinal);
            }
            else
            {
                IMAGE_IMPORT_BY_NAME* s = (IMAGE_IMPORT_BY_NAME*)SearchAddres(peFile, img->u1.AddressOfData, sizeof(IMAGE_IMPORT_BY_NAME));

                char* p = (char*)SearchAddres(peFile, peFile->impHeader[i].Name, sizeof(char));

                fprintf_s(f,"IMPORT Dll:%s Name:%s\n", p, s->Name);
            }
            img += 1;
            imgs += 1;
        }
    }
}

void print_dos_header(FORMATPE* peFile,FILE* f)
{
    print("e_magic", peFile->dosHeader->e_magic,f);
    print("e_lfanew", peFile->dosHeader->e_lfanew,f);
    fprintf_s(f,"\n");
}

void print_NT_headers(FORMATPE* peFile,FILE* f)
{
    print("signature", peFile->ntHeaders->Signature,f);
    print("machine", peFile->ntHeaders->FileHeader.Machine,f);
    print("Number of sections", peFile->ntHeaders->FileHeader.NumberOfSections,f);
    print("Characteristics", peFile->ntHeaders->FileHeader.Characteristics,f);
    print_rva_fa("AddresOfEntryPoint RVA:0x%X FA:0x%X\n", peFile->ntHeaders->OptionalHeader.AddressOfEntryPoint, peFile,f);
    print("ImageBase", peFile->ntHeaders->OptionalHeader.ImageBase,f);
    print("FileAlignment", peFile->ntHeaders->OptionalHeader.FileAlignment,f);
    print("SectionAlignment", peFile->ntHeaders->OptionalHeader.SectionAlignment,f);
    print("Subsystem", peFile->ntHeaders->OptionalHeader.Subsystem,f);
    fprintf_s(f,"\n");
}

int LoadFile(FORMATPE* peFile)
{
    int error = loadHeaders(peFile);

    if (error == INVALID_DOS)
    {
        return -1;
    }

    if (error == INVALID_NT)
    {
        return -1;
    }

    error = LoadSectionTable(peFile);

    if (error == INVALID_SECTIONS)
    {
        return -1;
    }

    //print_dos_header(peFile,f);

    //print_NT_headers(peFile,f);

    //PrintDataDirectory(peFile,f);

    //PrintSectionTable(peFile,f);

    error = LoadExportSimbols(peFile);

    if (error == INVALID_EXPORTS)
    {
        return -1;
    }

    error = LoadImportSymbols(peFile);

    if (error == INVALID_IMPORTS)
    {
        return -1;
    }

    //PrintImportSymbols(peFile,f);

    return 0;
}

