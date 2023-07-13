#include <Windows.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <ktmw32.h>

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
    DWORD privilege,
    bool bEnablePrivilege,
    bool IsThreadPrivilege,
    PBOOLEAN PreviousValue);

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

bool
RemoveKernelPurgeEAs(std::wstring filePath, bool bAllowUnsafe)
{
    bool bResult = false;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hTransaction = NULL;
    DWORD bytes = 0;
    FILE_DISPOSITION_INFO dispInfo = { TRUE };
    REPARSE_DATA_BUFFER reparse = {};

    if (INVALID_FILE_ATTRIBUTES == GetFileAttributesW(filePath.c_str()))
    {
        wprintf(L" [!] Invalid path: %ws\n", filePath.c_str());
        goto Cleanup;
    }

    filePath += L":RemoveKernelPurgeEAs";

    hTransaction = CreateTransaction(NULL, NULL, TRANSACTION_DO_NOT_PROMOTE, 0, 0, 0, NULL);
    hFile = CreateFileTransactedW(filePath.c_str(), FILE_WRITE_ATTRIBUTES | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS, nullptr, hTransaction, NULL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        if (!bAllowUnsafe)
        {
            printf(" [!] CreateFileTransactedW failed with GLE %u.\n", GetLastError());
            goto Cleanup;
        }

        printf(" [!] CreateFileTransactedW failed with GLE %u.  Retrying without TxF.\n", GetLastError());
        CloseHandle(hTransaction);
        hTransaction = NULL;

        hFile = CreateFileW(filePath.c_str(), FILE_WRITE_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, CREATE_ALWAYS,
            FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (INVALID_HANDLE_VALUE == hFile)
        {
            printf(" [!] CreateFileW failed with GLE %u\n", GetLastError());
            goto Cleanup;
        }

        printf(" [+] Created YOLO stream: %ws\n", filePath.c_str());
    }
    else
    {
        printf(" [+] Created stream in TxF: %ws\n", filePath.c_str());
    }

    reparse.ReparseTag = IO_REPARSE_TAG_UNHANDLED;
    if (!DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, &reparse,
        sizeof(reparse), nullptr, 0, &bytes, nullptr))
    {
        printf(" [!] DeviceIoControl(FSCTL_SET_REPARSE_POINT) failed with GLE %u\n", GetLastError());
        goto Cleanup;
    }
    printf(" [+] Reparse point created.\n");

    if (!DeviceIoControl(hFile, FSCTL_DELETE_REPARSE_POINT, &reparse,
        sizeof(reparse), nullptr, 0, &bytes, nullptr))
    {
        printf(" [!] DeviceIoControl(FSCTL_DELETE_REPARSE_POINT) failed with GLE %u\n", GetLastError());
        goto Cleanup;
    }
    printf(" [+] Reparse point removed.\n");

    if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &dispInfo, sizeof(dispInfo)))
    {
        printf(" [!] SetFileInformationByHandle(FileDispositionInfo) failed with GLE %u\n", GetLastError());
        goto Cleanup;
    }
    printf(" [+] Stream removed.\n");

    if (hTransaction)
    {
        CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;

        if (!CommitTransaction(hTransaction))
        {
            printf(" [!] Failed to commit transaction.\n");
        }
        else
        {
            printf(" [+] Transaction committed.\n");
        }
        CloseHandle(hTransaction);
    }
    bResult = true;

Cleanup:
    if (INVALID_HANDLE_VALUE != hFile)
    {
        CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE;
    }
    return bResult;
}

#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)

int wmain(int argc, wchar_t* argv[])
{
    bool bResult = false;
    bool bAllowUnsafe = true;
    BOOLEAN ignored = FALSE;

    if (argc < 2)
    {
        wprintf(L"Removes $Kernel.Purge EAs from the given file.\n\n");
        wprintf(L"Usage: %s <FILE> [--no-yolo]\n", argv[0]);
        wprintf(L"\t--no-yolo\tFail if the operation cannot be done with TxF.\n");
        return 0;
    }

    if (argc >= 3)
    {
        if (0 == _wcsicmp(argv[2], L"--no-yolo"))
        {
            bAllowUnsafe = false;
        }
    }

    RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &ignored);
    RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &ignored);

    bResult = RemoveKernelPurgeEAs(argv[1], bAllowUnsafe);
    if (bResult)
    {
        printf(" [+] Operation successful.\n");
    }
    else
    {
        printf(" [!] Operation failed.\n");
    }

    return bResult ? 0 : 1;
}
