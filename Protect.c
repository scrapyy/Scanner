#pragma once
#include "Protect.h"

unsigned int crc32b(unsigned char *message) {
    int i, j;
    unsigned int byte, crc, mask;

    i = 0;
    crc = 0xFFFFFFFF;
    while (i < 0x617) {
        byte = message[i];            // Get next byte.
        crc = crc ^ byte;
        for (j = 7; j >= 0; j--) {    // Do eight times.
            mask = (crc & 1)*-1;
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
        i = i + 1;
    }
    return ~crc;
}

int CheckSectionName(FORMATPE* peFile)
{
    int ct = peFile->ntHeaders->FileHeader.NumberOfSections - 1;
    if (strcmp((char*)peFile->seHeader[ct].Name, SECTION_NAME) != 0)
    {
        return CLEAN_FILE;
    }
    return INFECTED_FILE;
}

unsigned int Align_Section(FORMATPE* peFile, unsigned int size)
{
    unsigned int section_alignement = peFile->ntHeaders->OptionalHeader.FileAlignment;
    if (size%section_alignement == 0)
    {
        return size;
    }
    else
    {
        return (size / section_alignement + 1)*section_alignement;
    }
}

int CheckSectionSize(FORMATPE* peFile)
{
    unsigned int size = Align_Section(peFile, SECTION_SIZE);
    int ct = peFile->ntHeaders->FileHeader.NumberOfSections - 1;
    int u = peFile->seHeader[ct].SizeOfRawData;
    u++;
    if (peFile->seHeader[ct].SizeOfRawData != size)
    {
        return CLEAN_FILE;
    }
    return INFECTED_FILE;
}

int CheckEntryPoint(FORMATPE* peFile)
{
    int ct = peFile->ntHeaders->FileHeader.NumberOfSections - 1;
    unsigned int rva = peFile->seHeader[ct].VirtualAddress;

    if (rva != peFile->seHeader[ct].VirtualAddress)
    {
        return CLEAN_FILE;
    }
    return INFECTED_FILE;
}

int CheckSignatures(FORMATPE* peFile)
{
    if (peFile->dosHeader->e_magic != EXE_SIGNATURE)
    {
        return CLEAN_FILE;
    }

    if (peFile->ntHeaders->Signature != MACHINE_SIGNATURE)
    {
        return CLEAN_FILE;
    }

    if ((peFile->ntHeaders->FileHeader.Characteristics & 0x2000) != 0)
    {
        return CLEAN_FILE;
    }

    return INFECTED_FILE;
}

int CheckHash(FORMATPE* peFile)
{
    BYTE* entry = SearchAddres(peFile, peFile->seHeader[peFile->ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress, 4);
    unsigned char s[0x618] = { 0 };

    DWORD* aux = (DWORD*)(entry + 0x15);
    unsigned int key = aux[0];

    for (int i = 0; i < 0x37; i++)
        s[i] = entry[i];

    aux = (DWORD*)(long long*)((BYTE*)entry + 0x37);

    int ct = 0x37;

    for (int i = 0; i < 0xbc * 2; i += 2)
    {
        unsigned int rest = aux[i];
        unsigned int cat = aux[i + 1];
        unsigned long long o = 0;
        if (rest <= key)
        {
            o = (unsigned long long)cat * (unsigned long long)key + (unsigned long long)rest;

            s[ct] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 1] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 2] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 3] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 4] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 5] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 6] = (char)(o % (1 << 9));
            o = o >> 8;
            s[ct + 7] = (char)(o % (1 << 9));
        }
        else
        {
            s[ct] = (char)(cat % (1 << 9));
            cat = cat >> 8;
            s[ct + 1] = (char)(cat % (1 << 9));
            cat = cat >> 8;
            s[ct + 2] = (char)(cat % (1 << 9));
            cat = cat >> 8;
            s[ct + 3] = (char)(cat % (1 << 9));
            cat = cat >> 8;
            s[ct + 4] = (char)(rest % (1 << 9));
            rest = rest >> 8;
            s[ct + 5] = (char)(rest % (1 << 9));
            rest = rest >> 8;
            s[ct + 6] = (char)(rest % (1 << 9));
            rest = rest >> 8;
            s[ct + 7] = (char)(rest % (1 << 9));
        }
        ct += 8;
    }

    for (int i = 0; i < 4; i++)
        s[346 + i] = s[1509 + i] = s[1531 + i] = s[3 + i] = s[0x15 + i] = s[1539 + i] = s[1535 + i] = 0;


    unsigned long h1 = crc32b((unsigned char*)s);
    unsigned long h2 = crc32b((unsigned char*)(s + 1));

    if (h1 == FIRST_HASH && h2 == SECOND_HASH)
    {
        return INFECTED_FILE;
    }
    return CLEAN_FILE;
}


int ScanFile(FORMATPE* peFile)
{
    int type = CheckSectionName(peFile);

    if (type == CLEAN_FILE)
    {
        return CLEAN_FILE;
    }

    type = CheckSectionSize(peFile);

    if (type == CLEAN_FILE)
    {
        return CLEAN_FILE;
    }

    type = CheckEntryPoint(peFile);

    if (type == CLEAN_FILE)
    {
        return CLEAN_FILE;
    }

    type = CheckSignatures(peFile);

    if (type == CLEAN_FILE)
    {
        return CLEAN_FILE;
    }
    type = CheckHash(peFile);
    if (type == CLEAN_FILE)
    {
        return CLEAN_FILE;
    }
    return INFECTED_FILE;
}

