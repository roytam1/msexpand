/*
 * pefix.h -- old-file PE image normalisation and transform.
 *
 * Self-contained interface for the seed-preparation stage used by the PA19
 * apply path.  The transform is the exact inverse of what the reference
 * patcher does before decoding, so the LZXD stream's matches land on the
 * same bytes it was encoded against.
 */
#ifndef PEFIX_H
#define PEFIX_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#include <windows.h>
#include <imagehlp.h>
#include <stdlib.h>
#include <string.h>

#ifndef UNALIGNED
#define UNALIGNED
#endif
#ifndef DWORD_PTR
#define DWORD_PTR DWORD
#endif
#ifndef ULONG_PTR
#define ULONG_PTR ULONG
#endif

/* Older SDK headers lack the load-config directory layout. */
typedef struct _PEFIX_LOAD_CONFIG_DIRECTORY32 {
    DWORD Size;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD GlobalFlagsClear;
    DWORD GlobalFlagsSet;
    DWORD CriticalSectionDefaultTimeout;
    DWORD DeCommitFreeBlockThreshold;
    DWORD DeCommitTotalFreeThreshold;
    DWORD LockPrefixTable;
    DWORD MaximumAllocationSize;
    DWORD VirtualMemoryThreshold;
    DWORD ProcessHeapFlags;
    DWORD ProcessAffinityMask;
    WORD  CSDVersion;
    WORD  Reserved1;
    DWORD EditList;
    DWORD SecurityCookie;
    DWORD SEHandlerTable;
    DWORD SEHandlerCount;
} PEFIX_LOAD_CONFIG_DIRECTORY32, *PPEFIX_LOAD_CONFIG_DIRECTORY32;

typedef IMAGE_DOS_HEADER                UNALIGNED* UP_IMAGE_DOS_HEADER;
typedef IMAGE_NT_HEADERS32              UNALIGNED* UP_IMAGE_NT_HEADERS32;
typedef IMAGE_SECTION_HEADER            UNALIGNED* UP_IMAGE_SECTION_HEADER;
typedef IMAGE_EXPORT_DIRECTORY          UNALIGNED* UP_IMAGE_EXPORT_DIRECTORY;
typedef IMAGE_IMPORT_DESCRIPTOR         UNALIGNED* UP_IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_BY_NAME            UNALIGNED* UP_IMAGE_IMPORT_BY_NAME;
typedef IMAGE_THUNK_DATA32              UNALIGNED* UP_IMAGE_THUNK_DATA32;
typedef IMAGE_RESOURCE_DIRECTORY        UNALIGNED* UP_IMAGE_RESOURCE_DIRECTORY;
typedef IMAGE_RESOURCE_DIRECTORY_ENTRY  UNALIGNED* UP_IMAGE_RESOURCE_DIRECTORY_ENTRY;
typedef IMAGE_RESOURCE_DATA_ENTRY       UNALIGNED* UP_IMAGE_RESOURCE_DATA_ENTRY;
typedef IMAGE_RESOURCE_DIR_STRING_U     UNALIGNED* UP_IMAGE_RESOURCE_DIR_STRING_U;
typedef PEFIX_LOAD_CONFIG_DIRECTORY32   UNALIGNED* UP_IMAGE_LOAD_CONFIG_DIRECTORY32;
typedef IMAGE_BASE_RELOCATION           UNALIGNED* UP_IMAGE_BASE_RELOCATION;

typedef struct _RIFT_ENTRY {
    ULONG OldFileRva;
    ULONG NewFileRva;
} RIFT_ENTRY, *PRIFT_ENTRY;

typedef struct _RIFT_TABLE {
    ULONG       RiftEntryCount;
    ULONG       RiftEntryAlloc;
    PRIFT_ENTRY RiftEntryArray;
    PUCHAR      RiftUsageArray;
} RIFT_TABLE, *PRIFT_TABLE;

typedef struct _PATCH_IGNORE_RANGE {
    ULONG OffsetInOldFile;
    ULONG LengthInBytes;
} PATCH_IGNORE_RANGE, *PPATCH_IGNORE_RANGE;

typedef struct _PATCH_RETAIN_RANGE {
    ULONG OffsetInOldFile;
    ULONG LengthInBytes;
    ULONG OffsetInNewFile;
} PATCH_RETAIN_RANGE, *PPATCH_RETAIN_RANGE;

#ifndef bool
typedef int bool;
#endif
#ifndef byte
typedef unsigned char byte;
#endif
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef ROUNDUP2
#define ROUNDUP2(x, n) ((((ULONG)(x)) + (((ULONG)(n)) - 1)) & ~(((ULONG)(n)) - 1))
#endif
#ifndef ASSERT
#define ASSERT(a)
#endif

#define PATCH_OPTION_NO_BINDFIX    0x00010000
#define PATCH_OPTION_NO_LOCKFIX    0x00020000
#define PATCH_OPTION_NO_REBASE     0x00040000
#define PATCH_OPTION_NO_CHECKSUM   0x00200000
#define PATCH_OPTION_NO_RESTIMEFIX 0x00400000
#define PATCH_OPTION_NO_TIMESTAMP  0x00800000

#define X86_OPCODE_NOP  0x90
#define X86_OPCODE_LOCK 0xF0

#define PATCH_TRANSFORM_NO_RELOCS    0x00000001
#define PATCH_TRANSFORM_NO_IMPORTS   0x00000002
#define PATCH_TRANSFORM_NO_EXPORTS   0x00000004
#define PATCH_TRANSFORM_NO_RELJMPS   0x00000008
#define PATCH_TRANSFORM_NO_RELCALLS  0x00000010
#define PATCH_TRANSFORM_NO_RESOURCE  0x00000020

PVOID __fastcall MyVirtualAlloc(ULONG Size);
VOID  __fastcall MyVirtualFree(PVOID Allocation);

UP_IMAGE_NT_HEADERS32 __fastcall GetNtHeader(PVOID MappedFile, ULONG MappedFileSize);

BOOL
NormalizeCoffImage(
    UP_IMAGE_NT_HEADERS32 NtHeader,
    PUCHAR MappedFile,
    ULONG  FileSize,
    ULONG  OptionFlags,
    PVOID  OptionData,
    ULONG  NewFileCoffBase,
    ULONG  NewFileCoffTime
    );

BOOL
TransformCoffImage(
    ULONG  TransformOptions,
    UP_IMAGE_NT_HEADERS32 NtHeader,
    PUCHAR OldFileMapped,
    ULONG  OldFileSize,
    ULONG  NewFileResTime,
    PRIFT_TABLE RiftTable,
    PUCHAR HintMap
    );

USHORT ChkSum(USHORT Initial, PUSHORT Buffer, ULONG Bytes);

PVOID __fastcall
ImageDirectoryMappedAddress(
    UP_IMAGE_NT_HEADERS32 NtHeader,
    ULONG  DirectoryIndex,
    PULONG DirectorySize,
    PUCHAR MappedBase,
    ULONG  MappedSize
    );

int PeFixPrepareSeed(
    unsigned char *buf,
    unsigned long  len,
    unsigned long  optionFlags,
    unsigned long  transformOptions,
    unsigned long  coffBase,
    unsigned long  coffTime,
    const unsigned long *riftPairs,
    unsigned long  riftCount
    );

#endif /* PEFIX_H */
