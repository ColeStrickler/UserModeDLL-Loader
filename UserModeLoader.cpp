// UserModeLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "helpers.h"
#include <stdlib.h>
#include <stdio.h>
#include <iostream>


typedef struct relocBlock {
	WORD pageRVA;
	WORD type;
}RELOC_RECORD, *PRELOC_RECORD;

uintptr_t entry;

int main(int argc, char* argv[])
{

	if (argc < 2) {
		printf("[USAGE]    --->   UserModeLoader.exe <binary to load>");
	}

	BYTE* base = getFile(argv[1]);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	printf("[*] Performing signature check.....\n");
	BYTE sigCheck = *((BYTE*)&nt->Signature + 4);

	if (sigCheck == 0x64) {
		printf("[*] PE\\0\\0d found  --> 64 bit identified.\n");
	}
	else if (sigCheck == 0x4c) {
		printf("[*] PE\\0\\0L found  --> 32 bit identified.\n");
	}
	else {
		printf("[!] Unable to find PE signature in NT Headers. Found --> %x Exiting..\n", sigCheck);
		exit(-1);
	}

   

	DWORD nBytes = nt->OptionalHeader.SizeOfImage;
	DWORD freeSize = nt->OptionalHeader.SizeOfImage;
	uintptr_t baseAddress = (uintptr_t)VirtualAlloc(NULL, nBytes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// copy over headers
	nBytes = nt->OptionalHeader.SizeOfHeaders;
	memcpy((void*)baseAddress, (void*)base, nBytes);

	// copy over sections
	uintptr_t sectionAddress = (uintptr_t)&nt->OptionalHeader + (uintptr_t)nt->FileHeader.SizeOfOptionalHeader; // sections are immediately after the optional header
	DWORD nSections = nt->FileHeader.NumberOfSections;
	for (int i = 0; i < nSections; i++) {
		PIMAGE_SECTION_HEADER sectionHeader;
		uintptr_t addrInBuff;
		uintptr_t addrInMem;


		sectionHeader = (PIMAGE_SECTION_HEADER)sectionAddress;
		addrInBuff = (uintptr_t)base + sectionHeader->PointerToRawData;
		addrInMem = baseAddress + sectionHeader->VirtualAddress; // this is just adding the offset to the base of the newly allocated heap
		nBytes = sectionHeader->SizeOfRawData;

		printf("\t> Copying over (%s) section..\n", sectionHeader->Name);
		memcpy((void*)addrInMem, (void*)addrInBuff, nBytes);
		sectionAddress = sectionAddress + sizeof(IMAGE_SECTION_HEADER);

	}

	// populate the IAT
	PIMAGE_DATA_DIRECTORY dataDirectory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	printf("[*] dataDirectory->Size: %d\n", dataDirectory->Size);
	uintptr_t descriptorAddress = baseAddress + dataDirectory->VirtualAddress;
	PIMAGE_IMPORT_DESCRIPTOR descriptor = (PIMAGE_IMPORT_DESCRIPTOR)descriptorAddress;
	while (descriptor->Characteristics != 0) {
		uintptr_t nameAddr;
		HMODULE importedDLLBaseAddr;

		nameAddr = baseAddress + descriptor->Name; // this is the name of the DLL
		printf("[*] Processing imports for %s...\n", (char*)nameAddr);
		importedDLLBaseAddr = LoadLibraryA((LPCSTR)nameAddr);
		


		DWORD nFunctions = {0};
		DWORD nOrdinals= {0};

		uintptr_t firstThunkAddress = baseAddress + descriptor->FirstThunk;
		uintptr_t originalFirstThunkAddress = baseAddress + descriptor->OriginalFirstThunk;


		// both the IAT and ILT are arrays of IMAGE_THUNK_DATA structures
#ifdef _WIN64
		PIMAGE_THUNK_DATA64 IAT = (PIMAGE_THUNK_DATA64)firstThunkAddress;
		PIMAGE_THUNK_DATA64 ILT = (PIMAGE_THUNK_DATA64)originalFirstThunkAddress;
		uintptr_t flag = IMAGE_ORDINAL_FLAG64;
#else
		PIMAGE_THUNK_DATA32 IAT = (PIMAGE_THUNK_DATA32)firstThunkAddress;
		PIMAGE_THUNK_DATA32 ILT = (PIMAGE_THUNK_DATA32)originalFirstThunkAddress;
		uintptr_t flag = IMAGE_ORDINAL_FLAG32;
#endif

		while (IAT->u1.Function != 0) {
			// do not do anything for ordinal imports
			if (ILT->u1.Ordinal & flag) {
				printf("\t> Import by Ordinal\n");
				nOrdinals++;
			}
			else {
				PIMAGE_IMPORT_BY_NAME nameArray;
				uintptr_t funcNameAddress;

				nameArray = (PIMAGE_IMPORT_BY_NAME)(ILT->u1.AddressOfData);
				funcNameAddress = baseAddress + (uintptr_t)(nameArray->Name);
				printf("\t> Populating IAT with --> %s", (char*)funcNameAddress);
				if (strlen((char*)funcNameAddress) < 6) {
					printf("\t\t\t\t\t");
				}
				else if (strlen((char*)funcNameAddress) < 14) {
					printf("\t\t\t\t");
				}
				else if (strlen((char*)funcNameAddress) > 29) {
					printf("\t");
				}
				else if (strlen((char*)funcNameAddress) > 21) {
					printf("\t\t");
				}
				else {
					printf("\t\t\t");
				}
				printf("RVA --> 0x%p\n", IAT->u1.Function);


				IAT->u1.Function = (uintptr_t)GetProcAddress(importedDLLBaseAddr, (LPCSTR)funcNameAddress); /// update each IAT entry to point to actual routine address
				nFunctions++;
			}
			

			IAT++;
			ILT++;
		}

		

		descriptor += 1;
	}


	uintptr_t delta = baseAddress - nt->OptionalHeader.ImageBase;
	PIMAGE_DATA_DIRECTORY relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	uintptr_t tableEntryAddress = baseAddress + dataDirectory->VirtualAddress;
	PIMAGE_BASE_RELOCATION tableEntry = (PIMAGE_BASE_RELOCATION)tableEntryAddress;

	printf("[*] Fixing up relocation addresses.\n");
	while (tableEntry->SizeOfBlock > 0) {

		uintptr_t pageAddress;
		DWORD nRelocs;
		uintptr_t relocRecordAddress;
		PRELOC_RECORD relocRecord;
		DWORD i = 0;
		
		// calculate address of 4kb page
		pageAddress = (baseAddress + tableEntry->VirtualAddress);

		// Determine # of IMAGE_RELOC elements in the relocation block
		nRelocs = tableEntry->SizeOfBlock;
		nRelocs = nRelocs - sizeof(IMAGE_BASE_RELOCATION);
		nRelocs = nRelocs / sizeof(RELOC_RECORD);



		// address of 1st IMAGE_RELOC following IMAGE_BASE_RELOCATION
		relocRecordAddress = tableEntryAddress + sizeof(IMAGE_BASE_RELOCATION);
		relocRecord = (PRELOC_RECORD)relocRecordAddress;

		for (i = 0; i < nRelocs; i++) {
			uintptr_t fixupAddress;
			DWORD fixupType;


			// find fixup address within 4kb
			fixupAddress = pageAddress + relocRecord[i].pageRVA;
			fixupType = relocRecord[i].type;

			if (fixupType == IMAGE_REL_BASED_HIGH) {
				*(WORD*)fixupAddress += HIWORD(delta);
			}
			else if (fixupType == IMAGE_REL_BASED_LOW) {
				*(WORD*)fixupAddress += LOWORD(delta);
			}
			else if (fixupType == IMAGE_REL_BASED_HIGHLOW) {
				*(DWORD*)fixupAddress += delta;
			}

		}

		tableEntryAddress = tableEntryAddress + tableEntry->SizeOfBlock;
		tableEntry = (PIMAGE_BASE_RELOCATION)tableEntryAddress;

	}
	





	printf("[*] Loading finished successfully!\n");
	
}
