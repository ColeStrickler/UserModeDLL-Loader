#include "helpers.h"




BYTE* getFile(char* fileName) {

    HANDLE hFile = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, NULL, NULL);

    if (hFile != NULL) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
        ReadFile(hFile, fileData, fileSize, NULL, NULL);
        CloseHandle(hFile);
        return (BYTE*)fileData;
    }
    return NULL;

}