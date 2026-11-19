/*
 * pefix.c -- old-file image normalisation and PE transform.
 *
 * Prepares the LZXD seed dictionary: PE timestamp/checksum normalisation,
 * then canonicalisation of relocations, relative branches, imports and
 * exports driven by the patch RIFT map.  Deterministic, reverse of the
 * matching apply-side decoder.  Apply-side only.
 */
#define PATCH_APPLY_CODE_ONLY 1
#include "pefix.h"

#define MAX_SYMBOL_NAME_LENGTH  2048




typedef struct _RELOC_ARRAY_ENTRY RELOC_ARRAY_ENTRY, *PRELOC_ARRAY_ENTRY;

struct _RELOC_ARRAY_ENTRY {
    ULONG  RelocRva;
    UCHAR  RelocType;
    USHORT HighAdjValue;
    };




UP_IMAGE_NT_HEADERS32
__fastcall
GetNtHeader(
    IN PVOID MappedFile,
    IN ULONG MappedFileSize
    )
    {
    UP_IMAGE_DOS_HEADER   DosHeader;
    UP_IMAGE_NT_HEADERS32 RetHeader;
    UP_IMAGE_NT_HEADERS32 NtHeader;

    RetHeader = NULL;

    __try {

        if ( MappedFileSize >= 0x200 ) {

            DosHeader = (UP_IMAGE_DOS_HEADER) MappedFile;

            if ( DosHeader->e_magic == IMAGE_DOS_SIGNATURE ) {

                NtHeader = (UP_IMAGE_NT_HEADERS32)((PUCHAR) MappedFile + DosHeader->e_lfanew );

                if (((PUCHAR) NtHeader + sizeof( IMAGE_NT_HEADERS32 )) <= ((PUCHAR) MappedFile + MappedFileSize )) {

                    if ( NtHeader->Signature == IMAGE_NT_SIGNATURE ) {

                        if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

                            RetHeader = NtHeader;

                            }
                        }
                    }
                }
            }
        }
    __except( EXCEPTION_EXECUTE_HANDLER ) {
        }

    return RetHeader;
    }


BOOL
__fastcall
IsImageRvaInExecutableSection(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG Rva
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG SectionCount;
    ULONG i;

    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {
        if (( Rva >= SectionHeader[ i ].VirtualAddress ) &&
            ( Rva <  SectionHeader[ i ].VirtualAddress + SectionHeader[ i ].Misc.VirtualSize )) {

            return (( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) ? TRUE : FALSE );
            }
        }

    return FALSE;
    }


ULONG
__fastcall
ImageRvaToFileOffset(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG Rva
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG SectionCount;
    ULONG i;

    if ( Rva < NtHeader->OptionalHeader.SizeOfHeaders ) {
        return Rva;
        }

    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {
        if (( Rva >= SectionHeader[ i ].VirtualAddress ) &&
            ( Rva <  SectionHeader[ i ].VirtualAddress + SectionHeader[ i ].SizeOfRawData )) {

            return ( SectionHeader[ i ].PointerToRawData + ( Rva - SectionHeader[ i ].VirtualAddress ));
            }
        }

    return 0;
    }


PVOID
__fastcall
ImageRvaToMappedAddress(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG Rva,
    IN PVOID MappedBase,
    IN ULONG MappedSize
    )
    {
    ULONG MappedOffset = ImageRvaToFileOffset( NtHeader, Rva );

    if (( MappedOffset ) && ( MappedOffset < MappedSize )) {
        return ((PUCHAR)MappedBase + MappedOffset );
        }

    return NULL;
    }

ULONG
__fastcall
ImageVaToFileOffset(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG Va
    )
    {
    return ImageRvaToFileOffset( NtHeader, Va - NtHeader->OptionalHeader.ImageBase );
    }


PVOID
__fastcall
ImageVaToMappedAddress(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG Va,
    IN PVOID MappedBase,
    IN ULONG MappedSize
    )
    {
    return ImageRvaToMappedAddress( NtHeader, Va - NtHeader->OptionalHeader.ImageBase, MappedBase, MappedSize );
    }


ULONG
__fastcall
ImageDirectoryRvaAndSize(
    IN  UP_IMAGE_NT_HEADERS32 NtHeader,
    IN  ULONG  DirectoryIndex,
    OUT PULONG DirectorySize
    )
    {
    if ( DirectoryIndex < NtHeader->OptionalHeader.NumberOfRvaAndSizes ) {

        if ( DirectorySize ) {
            *DirectorySize = NtHeader->OptionalHeader.DataDirectory[ DirectoryIndex ].Size;
            }

        return NtHeader->OptionalHeader.DataDirectory[ DirectoryIndex ].VirtualAddress;
        }

    return 0;
    }


ULONG
__fastcall
ImageDirectoryOffsetAndSize(
    IN  UP_IMAGE_NT_HEADERS32 NtHeader,
    IN  ULONG  DirectoryIndex,
    OUT PULONG DirectorySize
    )
    {
    ULONG Rva = ImageDirectoryRvaAndSize( NtHeader, DirectoryIndex, DirectorySize );

    if ( Rva ) {
        return ImageRvaToFileOffset( NtHeader, Rva );
        }

    return 0;
    }


PVOID
__fastcall
ImageDirectoryMappedAddress(
    IN  UP_IMAGE_NT_HEADERS32 NtHeader,
    IN  ULONG  DirectoryIndex,
    OUT PULONG DirectorySize,
    IN  PUCHAR MappedBase,
    IN  ULONG  MappedSize
    )
    {
    PUCHAR Directory;
    ULONG  LocalSize;
    ULONG  Rva;

    Rva = ImageDirectoryRvaAndSize( NtHeader, DirectoryIndex, &LocalSize );

    Directory = ImageRvaToMappedAddress( NtHeader, Rva, MappedBase, MappedSize );

    if (( Directory ) && (( Directory + LocalSize ) <= ( MappedBase + MappedSize ))) {

        if ( DirectorySize ) {
            *DirectorySize = LocalSize;
            }

        return Directory;
        }

    return NULL;
    }


ULONG
__fastcall
FileOffsetToImageRva(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG FileOffset
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG SectionCount;
    ULONG i;

    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {
        if (( FileOffset >= SectionHeader[ i ].PointerToRawData ) &&
            ( FileOffset <  SectionHeader[ i ].PointerToRawData + SectionHeader[ i ].SizeOfRawData )) {

            return ( SectionHeader[ i ].VirtualAddress + ( FileOffset - SectionHeader[ i ].PointerToRawData ));
            }
        }

    return 0;
    }


ULONG
MappedAddressToImageRva(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID MappedAddress,
    IN PVOID MappedFile
    )
    {
    LONG FileOffset = (LONG)((PUCHAR)MappedAddress - (PUCHAR)MappedFile);

    if ( FileOffset > 0 ) {
        return FileOffsetToImageRva( NtHeader, FileOffset );
        }

    return 0;
    }


BOOL
RebaseMappedImage(
    IN PUCHAR MappedFile,
    IN ULONG  FileSize,
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN ULONG  NewBase
    )
    {
    UP_IMAGE_BASE_RELOCATION RelocBlock;
    LONG                   RelocAmount;
    LONG                   RelocDirRemaining;
    ULONG                  RelocDirSize;
    PUCHAR                 RelocBlockMa;
    PUCHAR                 RelocFixupMa;
    ULONG                  RelocCount;
    USHORT UNALIGNED*      RelocEntry;
    PUCHAR                 MappedFileEnd;
    BOOL                   Modified;

    //
    //  Carefully rebase the image, ignoring invalid info as much as possible
    //  without taking an access violation.  We don't want to use try/except
    //  here because this code needs to be workable without any imports from
    //  kernel32.dll.  This code is not intended to catch errors in invalid
    //  rebase info -- it is intended to silently do the best it can at
    //  rebasing the image in memory.  If the rebase info is valid, it will
    //  correctly rebase the image.  If the rebase info is not valid, it will
    //  attempt to avoid causing an access violation.
    //

    ASSERT( NtHeader->OptionalHeader.ImageBase != NewBase );
    ASSERT(( NewBase & 0x0000FFFF ) == 0 );
    ASSERT(( NewBase & 0xFFFF0000 ) != 0 );

    Modified      = FALSE;
    MappedFileEnd = MappedFile + FileSize;
    RelocAmount   = NewBase - NtHeader->OptionalHeader.ImageBase;

    RelocBlock = ImageDirectoryMappedAddress( NtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocDirSize, MappedFile, FileSize );

    if ( RelocBlock ) {

        NtHeader->OptionalHeader.ImageBase = NewBase;
        Modified = TRUE;

        RelocDirRemaining = (LONG)RelocDirSize;

        while ( RelocDirRemaining > 0 ) {

            if (( RelocBlock->SizeOfBlock <= (ULONG)RelocDirRemaining ) &&
                ( RelocBlock->SizeOfBlock > sizeof( IMAGE_BASE_RELOCATION ))) {

                //
                //  ImageRvaToMappedAddress returns NULL if the Rva is zero,
                //  but that is a valid base address of a reloc block.  Use
                //  ImageRvaToFileOffset instead.
                //

                RelocBlockMa = MappedFile + ImageRvaToFileOffset( NtHeader, RelocBlock->VirtualAddress );

                if ( RelocBlockMa ) {

                    RelocEntry = (PUSHORT)((PUCHAR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ));
                    RelocCount = ( RelocBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( USHORT );

                    while ( RelocCount-- ) {

                        RelocFixupMa = RelocBlockMa + ( *RelocEntry & 0x0FFF );

                        if ( RelocFixupMa < MappedFileEnd ) {

                            switch ( *RelocEntry >> 12 ) {

                                case IMAGE_REL_BASED_HIGHLOW:

                                    *(UNALIGNED LONG *)RelocFixupMa += RelocAmount;
                                    break;

                                case IMAGE_REL_BASED_LOW:

                                    *(UNALIGNED USHORT *)RelocFixupMa = (USHORT)( *(UNALIGNED SHORT *)RelocFixupMa + RelocAmount );
                                    break;

                                case IMAGE_REL_BASED_HIGH:

                                    *(UNALIGNED USHORT *)RelocFixupMa = (USHORT)((( *(UNALIGNED USHORT *)RelocFixupMa << 16 ) + RelocAmount ) >> 16 );
                                    break;

                                case IMAGE_REL_BASED_HIGHADJ:

                                    ++RelocEntry;
                                    --RelocCount;

                                    *(UNALIGNED USHORT *)RelocFixupMa = (USHORT)((( *(UNALIGNED USHORT *)RelocFixupMa << 16 ) + *(UNALIGNED SHORT *)RelocEntry + RelocAmount + 0x8000 ) >> 16 );
                                    break;

                                //
                                //  Just skip and continue if we don't
                                //  recognize the reloc type.
                                //

                                }
                            }

                        ++RelocEntry;

                        }
                    }
                }

            RelocDirRemaining -= RelocBlock->SizeOfBlock;
            RelocBlock = (UP_IMAGE_BASE_RELOCATION)((PUCHAR)RelocBlock + RelocBlock->SizeOfBlock );

            }
        }

    return Modified;
    }


BOOL
UnBindMappedImage(
    IN PUCHAR MappedFile,
    IN ULONG  FileSize,
    IN UP_IMAGE_NT_HEADERS32 NtHeader
    )
    {
    UP_IMAGE_SECTION_HEADER  SectionHeader;
    UP_IMAGE_IMPORT_DESCRIPTOR ImportDesc;
    ULONG                    SectionCount;
    DWORDLONG                SectionName;
    PVOID                    BoundImportDir;
    ULONG                    BoundImportSize;
    ULONG UNALIGNED*         OriginalIat;
    ULONG UNALIGNED*         BoundIat;
    PUCHAR                   MappedFileEnd;
    BOOL                     Modified;
    ULONG                    i;

    Modified       = FALSE;
    MappedFileEnd  = MappedFile + FileSize;
    BoundImportDir = ImageDirectoryMappedAddress( NtHeader, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, &BoundImportSize, MappedFile, FileSize );

    if ( BoundImportDir ) {

        //
        //  Zero the bound import directory and pointers to bound
        //  import directory.
        //

        ZeroMemory( BoundImportDir, BoundImportSize );

        NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].VirtualAddress = 0;
        NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ].Size           = 0;

        Modified = TRUE;
        }

    //
    //  Now walk imports and zero the TimeDate and
    //  ForwarderChain fields.
    //

    ImportDesc = ImageDirectoryMappedAddress( NtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, NULL, MappedFile, FileSize );

    if ( ImportDesc ) {

        while (((ULONG_PTR)ImportDesc < ((ULONG_PTR)MappedFileEnd - sizeof( IMAGE_IMPORT_DESCRIPTOR ))) &&
               ( ImportDesc->Characteristics )) {

            if ( ImportDesc->TimeDateStamp ) {

                //
                //  This is a bound import.  Copy the unbound
                //  IAT over the bound IAT to restore.
                //

                ImportDesc->TimeDateStamp = 0;
                Modified = TRUE;

                OriginalIat = ImageRvaToMappedAddress( NtHeader, (ULONG)ImportDesc->OriginalFirstThunk, MappedFile, FileSize );
                BoundIat    = ImageRvaToMappedAddress( NtHeader, (ULONG)ImportDesc->FirstThunk,         MappedFile, FileSize );

                if (( OriginalIat ) && ( BoundIat )) {

                    while (((PUCHAR)OriginalIat < MappedFileEnd ) &&
                           ((PUCHAR)BoundIat    < MappedFileEnd ) &&
                           ( *OriginalIat )) {

                        *BoundIat++ = *OriginalIat++;
                        }
                    }
                }

            if ( ImportDesc->ForwarderChain ) {
                 ImportDesc->ForwarderChain = 0;
                 Modified = TRUE;
                 }

            ++ImportDesc;
            }
        }

    //
    //  The bind utility marks the .idata section as read-only so we want to
    //  change it back to read-write.
    //

    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {

        SectionName = *(UNALIGNED DWORDLONG*)( &SectionHeader[ i ].Name );
        SectionName |= 0x2020202020202020;  // fast lower case

        if ( SectionName == 0x202061746164692E ) {      // ".idata  "

            if ( ! ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )) {

                SectionHeader[ i ].Characteristics |= ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE );
                Modified = TRUE;
                }

            break;
            }
        }

    return Modified;
    }


BOOL
SmashLockPrefixesInMappedImage(
    IN PUCHAR MappedFile,
    IN ULONG  FileSize,
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN UCHAR  NewOpCode      // X86_OPCODE_NOP or X86_OPCODE_LOCK
    )
    {
    UP_IMAGE_LOAD_CONFIG_DIRECTORY32 LoadConfig;
    ULONG UNALIGNED* LockPrefixEntry;
    PUCHAR LockPrefixInstruction;
    BOOL   Modified;

    Modified   = FALSE;
    LoadConfig = ImageDirectoryMappedAddress( NtHeader, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, NULL, MappedFile, FileSize );

    if ( LoadConfig ) {

        if ( LoadConfig->LockPrefixTable ) {

            //
            //  The LoadConfig->LockPrefixTable field and
            //  the lock prefix addresses are stored in the
            //  image as image VA, not RVA values.
            //

            LockPrefixEntry = ImageVaToMappedAddress( NtHeader, LoadConfig->LockPrefixTable, MappedFile, FileSize );

            if ( LockPrefixEntry ) {

                while ( *LockPrefixEntry ) {

                    LockPrefixInstruction = ImageVaToMappedAddress( NtHeader, *LockPrefixEntry, MappedFile, FileSize );

                    if ( LockPrefixInstruction ) {

                        if ( *LockPrefixInstruction != NewOpCode ) {

                            //
                            //  Lock prefix instruction is not what we want,
                            //  so modify it.
                            //

                            *LockPrefixInstruction = NewOpCode;
                            Modified = TRUE;
                            }
                        }

                    ++LockPrefixEntry;

                    }
                }
            }
        }

    return Modified;
    }


USHORT
ChkSum(
    IN USHORT  Initial,
    IN PUSHORT Buffer,
    IN ULONG   Bytes
    )
    {
    USHORT UNALIGNED* p = Buffer;
    ULONG WordsRemaining = Bytes / 2;
    ULONG WordsInChunk;
    ULONG SumChunk;
    ULONG SumTotal;

    SumTotal = Initial;

    while ( WordsRemaining ) {

        WordsInChunk = WordsRemaining;

        if ( WordsInChunk > 0x10000 ) {
             WordsInChunk = 0x10000;
             }

        WordsRemaining -= WordsInChunk;

        SumChunk = 0;

        do  {
            SumChunk += *p++;
            }
        while ( --WordsInChunk != 0 );

        SumTotal += ( SumChunk >> 16 ) + ( SumChunk & 0xFFFF );
        }

    if ( Bytes % 2 ) {

        SumTotal += *((PBYTE) p);
        }

    return (USHORT)(( SumTotal >> 16 ) + ( SumTotal & 0xFFFF ));
    }


BOOL
NormalizeCoffImage(
    IN OUT UP_IMAGE_NT_HEADERS32 NtHeader,
    IN OUT PUCHAR MappedFile,
    IN     ULONG  FileSize,
    IN     ULONG  OptionFlags,
    IN     PVOID  OptionData,
    IN     ULONG  NewFileCoffBase,
    IN     ULONG  NewFileCoffTime
    )
    {
    BOOL Modified = FALSE;

    UNREFERENCED_PARAMETER( OptionData );

    if ( ! ( OptionFlags & PATCH_OPTION_NO_REBASE )) {

        if (( NewFileCoffTime != 0 ) && ( NtHeader->FileHeader.TimeDateStamp != NewFileCoffTime )) {
             NtHeader->FileHeader.TimeDateStamp = NewFileCoffTime;
             Modified = TRUE;
             }

        if (( NewFileCoffBase != 0 ) && ( NtHeader->OptionalHeader.ImageBase != NewFileCoffBase )) {
            Modified |= RebaseMappedImage( MappedFile, FileSize, NtHeader, NewFileCoffBase );
            }
        }

    if ( ! ( OptionFlags & PATCH_OPTION_NO_BINDFIX )) {
        Modified |= UnBindMappedImage( MappedFile, FileSize, NtHeader );
        }

    if ( ! ( OptionFlags & PATCH_OPTION_NO_LOCKFIX )) {
        Modified |= SmashLockPrefixesInMappedImage( MappedFile, FileSize, NtHeader, X86_OPCODE_LOCK );
        }

    //
    //  If the target file has zero checksum (PATCH_OPTION_NO_CHECKSUM),
    //  set the checksum in this image to zero.
    //
    //  Otherwise, if we either modified the image or if the image has
    //  a zero checksum, recompute the correct checksum.
    //

    if ( OptionFlags & PATCH_OPTION_NO_CHECKSUM ) {

        if ( NtHeader->OptionalHeader.CheckSum != 0 ) {
             NtHeader->OptionalHeader.CheckSum = 0;
             Modified = TRUE;
             }
        }

    else {

        if ( Modified ) {
             (ULONG)( NtHeader->OptionalHeader.CheckSum ) = 0;
             NtHeader->OptionalHeader.CheckSum = ChkSum( 0, (PVOID)MappedFile, FileSize ) + FileSize;
             }
        }

    return Modified;
    }


//
//  For some odd reason, the VC4 compiler says there is unreachable code
//  in the GetNewRvaFromRiftTable and FindRiftTableEntryForOldRva functions,
//  but I can't find it by inspection, and the VC5 and VC6 compilers don't
//  complain about it, so it's probably just a VC4 issue.  So, if the compiler
//  version is previous to VC5, disable this particular warning.
//

#if ( _MSC_VER < 1100 )
#pragma warning( disable: 4702 )    // unreachable code
#endif

ULONG
__fastcall
GetNewRvaFromRiftTable(
    IN PRIFT_TABLE RiftTable,
    IN ULONG OldRva
    )
    {
    PRIFT_ENTRY RiftEntryArray;
    ULONG NewRva;
    ULONG Index;
    ULONG MinIndexInclusive;
    ULONG MaxIndexExclusive;
    LONG  Displacement;
    BOOL  Found;

    //
    //  Rift table is in sorted order by OldRva, so do a binary search for
    //  matching or nearest preceding OldRva value.
    //

    RiftEntryArray    = RiftTable->RiftEntryArray;
    MaxIndexExclusive = RiftTable->RiftEntryCount;
    MinIndexInclusive = 0;
    Index             = 0;
    Found             = FALSE;

    while (( ! Found ) && ( MinIndexInclusive < MaxIndexExclusive )) {

        Index = ( MinIndexInclusive + MaxIndexExclusive ) / 2;    // won't overflow

        if ( RiftEntryArray[ Index ].OldFileRva < OldRva ) {
            MinIndexInclusive = Index + 1;
            }
        else if ( RiftEntryArray[ Index ].OldFileRva > OldRva ) {
            MaxIndexExclusive = Index;
            }
        else {
            Found = TRUE;
            break;
            }
        }

    if ( ! Found ) {

        //
        //  MinIndex is pointing to next highest entry, which could also be
        //  the zeroth entry if the search value was lower than anything in
        //  the table.
        //

        if ( MinIndexInclusive == 0 ) {
            return OldRva;  // zero displacement
            }

        Index = MinIndexInclusive - 1;
        }

    Displacement = (LONG)( RiftEntryArray[ Index ].NewFileRva - RiftEntryArray[ Index ].OldFileRva );


    NewRva = OldRva + Displacement;

    return NewRva;
    }


ULONG
__fastcall
FindRiftTableEntryForOldRva(
    IN PRIFT_TABLE RiftTable,
    IN ULONG OldRva
    )
    {
    PRIFT_ENTRY RiftEntryArray;
    ULONG MinIndexInclusive;
    ULONG MaxIndexExclusive;
    ULONG Index;
    BOOL  Found;

    //
    //  Rift table is in sorted order by OldRva, so do a binary search for
    //  matching or nearest preceding OldRva value.
    //

    RiftEntryArray    = RiftTable->RiftEntryArray;
    MaxIndexExclusive = RiftTable->RiftEntryCount;
    MinIndexInclusive = 0;
    Index             = 0;
    Found             = FALSE;

    while (( ! Found ) && ( MinIndexInclusive < MaxIndexExclusive )) {

        Index = ( MinIndexInclusive + MaxIndexExclusive ) / 2;    // won't overflow

        if ( RiftEntryArray[ Index ].OldFileRva < OldRva ) {
            MinIndexInclusive = Index + 1;
            }
        else if ( RiftEntryArray[ Index ].OldFileRva > OldRva ) {
            MaxIndexExclusive = Index;
            }
        else {
            Found = TRUE;
            break;
            }
        }

    if ( ! Found ) {

        //
        //  MinIndex is pointing to next highest entry, which could also be
        //  the zeroth entry if the search value was lower than anything in
        //  the table.
        //

        if ( MinIndexInclusive == 0 ) {
            return 0;
            }

        Index = MinIndexInclusive - 1;
        }

    return Index;
    }


#if ( _MSC_VER < 1100 )
#pragma warning( default: 4702 )    // unreachable code
#endif


VOID
__inline
ChangeOldRvaToNewRva(
    IN PRIFT_TABLE RiftTable,
    IN OUT PVOID AddressOfRvaToChange
    )
    {
    //
    //  Assuming all addresses of RVAs in a PE image are aligned.
    //

    ULONG UNALIGNED* RvaToChange = AddressOfRvaToChange;

    *RvaToChange = GetNewRvaFromRiftTable(
                       RiftTable,
                       *RvaToChange
                       );
    }


VOID
__inline
SwapRelocs(
    PRELOC_ARRAY_ENTRY One,
    PRELOC_ARRAY_ENTRY Two
    )
    {
    RELOC_ARRAY_ENTRY Tmp;

    Tmp  = *One;
    *One = *Two;
    *Two =  Tmp;
    }


VOID
__fastcall
RelocQsort(
    PRELOC_ARRAY_ENTRY LowerBound,
    PRELOC_ARRAY_ENTRY UpperBound
    )
    {
    PRELOC_ARRAY_ENTRY Lower = LowerBound;
    PRELOC_ARRAY_ENTRY Upper = UpperBound;
    PRELOC_ARRAY_ENTRY Pivot = Lower + (( Upper - Lower ) / 2 );
    ULONG PivotRva = Pivot->RelocRva;

    do  {

        while (( Lower <= Upper ) && ( Lower->RelocRva <= PivotRva )) {
            ++Lower;
            }

        while (( Upper >= Lower ) && ( Upper->RelocRva >= PivotRva )) {
            --Upper;
            }

        if ( Lower < Upper ) {
            SwapRelocs( Lower++, Upper-- );
            }
        }

    while ( Lower <= Upper );

    if ( Lower < Pivot ) {
        SwapRelocs( Lower, Pivot );
        Pivot = Lower;
        }
    else if ( Upper > Pivot ) {
        SwapRelocs( Upper, Pivot );
        Pivot = Upper;
        }

    if ( LowerBound < ( Pivot - 1 )) {
        RelocQsort( LowerBound, Pivot - 1 );
        }

    if (( Pivot + 1 ) < UpperBound ) {
        RelocQsort( Pivot + 1, UpperBound );
        }
    }


VOID
TransformOldFile_PE_Relocations(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID       FileMappedImage,
    IN ULONG       FileSize,
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR      HintMap
    )
    {
    PUCHAR  MappedFile;
    PUCHAR  MappedFileEnd;
    ULONG   ImageBaseVa;
    ULONG   ImageLastVa;
    PUCHAR  ImageFirstSectionMa;     // Mapped address
    ULONG   ImageFirstSectionVa;     // Virtual address
    ULONG   RelocDirOff;
    ULONG   RelocDirSize;
    LONG    RelocDirRemaining;
    UP_IMAGE_BASE_RELOCATION RelocBlock;
    UP_IMAGE_BASE_RELOCATION RelocBlockBaseMa;        // Mapped address
    ULONG   RelocBlockBaseVa;        // Virtual address
    ULONG   RelocCount;
    USHORT UNALIGNED* RelocEntry;
    USHORT UNALIGNED* RelocFirst;
    UCHAR   RelocType;
    PUCHAR  RelocFixupMa;            // Mapped address
    ULONG   RelocFixupVa;            // Virtual address
    ULONG   RelocFixupRva;
    ULONG   RelocTargetVa;           // Virtual address
    ULONG   RelocTargetRva;
    ULONG   NewRva;
    ULONG   NewVa;
    PRELOC_ARRAY_ENTRY RelocArray;
    ULONG   RelocArrayCount;
    ULONG   RelocArrayIndex;
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG     SectionCount;
    DWORDLONG SectionName;
    PUCHAR  p;
    ULONG   i;

#ifdef TESTCODE

    ULONG CountRelocChanges = 0;

#endif // TESTCODE

    MappedFile    = FileMappedImage;
    MappedFileEnd = MappedFile + FileSize;
    ImageBaseVa   = NtHeader->OptionalHeader.ImageBase;
    RelocDirOff   = ImageDirectoryOffsetAndSize( NtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, &RelocDirSize );

    if (( RelocDirOff ) && (( RelocDirOff + RelocDirSize ) <= FileSize )) {

        memset( HintMap + RelocDirOff, 0x01, RelocDirSize );  // may need to be OR'd if other bits are used

        //  allocate an array for the new reloc entries, approximating the needed size

        RelocArray = MyVirtualAlloc( sizeof( *RelocArray ) * ( RelocDirSize / sizeof(USHORT)));

        if ( RelocArray != NULL ) {

            RelocArrayCount = 0;

            RelocBlock = (UP_IMAGE_BASE_RELOCATION)( MappedFile + RelocDirOff );

            RelocDirRemaining = (LONG)RelocDirSize;

            while ( RelocDirRemaining > 0 ) {

                if (( RelocBlock->SizeOfBlock <= (ULONG)RelocDirRemaining ) &&
                    ( RelocBlock->SizeOfBlock > sizeof( IMAGE_BASE_RELOCATION ))) {

                    //
                    //  ImageRvaToMappedAddress returns NULL if the Rva is zero,
                    //  but that is a valid base address of a reloc block.  Use
                    //  ImageRvaToFileOffset instead.
                    //

                    RelocBlockBaseMa = (UP_IMAGE_BASE_RELOCATION)( MappedFile + ImageRvaToFileOffset( NtHeader, RelocBlock->VirtualAddress ));

                    if ( RelocBlockBaseMa ) {

                        RelocBlockBaseVa = RelocBlock->VirtualAddress + ImageBaseVa;
                        RelocEntry       = (PUSHORT)((PUCHAR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ));
                        RelocCount       = ( RelocBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( USHORT );

                        while ( RelocCount-- ) {

                            RelocType = (UCHAR)( *RelocEntry >> 12 );

                            if ( RelocType != IMAGE_REL_BASED_ABSOLUTE ) {

                                RelocFixupMa  = (PUCHAR)RelocBlockBaseMa + ( *RelocEntry & 0x0FFF );
                                RelocFixupVa  = RelocBlockBaseVa + ( *RelocEntry & 0x0FFF );
                                RelocFixupRva = RelocFixupVa - ImageBaseVa;

                                RelocArray[ RelocArrayCount ].RelocRva  = GetNewRvaFromRiftTable(
                                                                              RiftTable,
                                                                              RelocFixupRva
                                                                              );

                                RelocArray[ RelocArrayCount ].RelocType = RelocType;

                                switch ( RelocType ) {

                                    case IMAGE_REL_BASED_HIGHLOW:

                                        if ( RelocFixupMa < MappedFileEnd ) {

                                            *(UNALIGNED ULONG *)( HintMap + ( RelocFixupMa - MappedFile )) |= 0x01010101;

                                            //
                                            //  Target is a 32-bit VA that we want to
                                            //  change to the corresponding VA in the
                                            //  new file.
                                            //

                                            RelocTargetVa  = *(UNALIGNED ULONG *) RelocFixupMa;
                                            RelocTargetRva = RelocTargetVa - ImageBaseVa;

                                            NewRva = GetNewRvaFromRiftTable(
                                                         RiftTable,
                                                         RelocTargetRva
                                                         );

                                            if ( NewRva != RelocTargetRva ) {

                                                NewVa = NewRva + ImageBaseVa;
                                                *(UNALIGNED ULONG *) RelocFixupMa = NewVa;
#ifdef TESTCODE
                                                ++CountRelocChanges;
#endif // TESTCODE
                                                }

                                            }

                                        break;

                                    case IMAGE_REL_BASED_LOW:
                                    case IMAGE_REL_BASED_HIGH:

                                        if ( RelocFixupMa < MappedFileEnd ) {
                                            *(UNALIGNED USHORT *)( HintMap + ( RelocFixupMa - MappedFile )) |= 0x0101;
                                            }

                                        break;

                                    case IMAGE_REL_BASED_HIGHADJ:

                                        if ( RelocFixupMa < MappedFileEnd ) {
                                            *(UNALIGNED USHORT *)( HintMap + ( RelocFixupMa - MappedFile )) |= 0x0101;
                                            }

                                        ++RelocEntry;
                                        --RelocCount;

                                        RelocArray[ RelocArrayCount ].HighAdjValue = *RelocEntry;

                                        break;
                                    }

                                ++RelocArrayCount;
                                }

                            ++RelocEntry;
                            }
                        }
                    }

                RelocDirRemaining -= RelocBlock->SizeOfBlock;
                RelocBlock = (UP_IMAGE_BASE_RELOCATION)((PUCHAR)RelocBlock + RelocBlock->SizeOfBlock );
                }

#ifdef TESTCODE

            printf( "\r%9d modified reloc targets\n", CountRelocChanges );

#endif TESTCODE

            //
            //  Now we want to reconstruct the .reloc table based on the new values
            //  hoping that it will more closely match the .reloc table in the new
            //  file.
            //
            //  First we want to sort our RelocArray by Rva.
            //

            if ( RelocArrayCount > 1 ) {
                RelocQsort( &RelocArray[ 0 ], &RelocArray[ RelocArrayCount - 1 ] );

#ifdef TESTCODE

                for ( i = 0; i < RelocArrayCount - 1; i++ ) {
                    if ( RelocArray[ i ].RelocRva > RelocArray[ i + 1 ].RelocRva ) {

                        printf( "\nReloc sort failed at index %d of %d\n", i, RelocArrayCount );

                        for ( i = 0; i < RelocArrayCount; i++ ) {
                            printf( "%08X\n", RelocArray[ i ].RelocRva );
                            }

                        exit( 1 );
                        break;
                        }
                    }

#endif // TESTCODE

                }

            RelocDirRemaining = (LONG)RelocDirSize;

            //
            //  Look for .reloc section to determine max size we can use for new
            //  .reloc data (may be bigger than old RelocDirSize).
            //

            SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
            SectionCount  = NtHeader->FileHeader.NumberOfSections;

            for ( i = 0; i < SectionCount; i++ ) {

                SectionName = *(UNALIGNED DWORDLONG*)( &SectionHeader[ i ].Name );
                SectionName |= 0x2020202020202020;  // fast lower case

                if ( SectionName == 0x2020636F6C65722E ) {      // ".reloc  "

                    if (( RelocDirOff >= SectionHeader[ i ].PointerToRawData ) &&
                        ( RelocDirOff <  SectionHeader[ i ].PointerToRawData + SectionHeader[ i ].SizeOfRawData )) {

                        RelocDirRemaining = ( SectionHeader[ i ].PointerToRawData + SectionHeader[ i ].SizeOfRawData ) - RelocDirOff;
                        }
                    }
                }

            RelocDirRemaining &= ~1;    // force to even value
            RelocBlock = (UP_IMAGE_BASE_RELOCATION)( MappedFile + RelocDirOff );
            RelocArrayIndex = 0;

            while (( RelocDirRemaining > sizeof( IMAGE_BASE_RELOCATION )) &&
                   ( RelocArrayIndex < RelocArrayCount )) {

                RelocBlock->VirtualAddress = ( RelocArray[ RelocArrayIndex ].RelocRva & 0xFFFFF000 );
                RelocFirst = RelocEntry    = (PUSHORT)((PUCHAR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ));
                RelocDirRemaining         -= sizeof( IMAGE_BASE_RELOCATION );

                while (( RelocDirRemaining > 0 ) &&
                       ( RelocArrayIndex < RelocArrayCount ) &&
                       (( RelocArray[ RelocArrayIndex ].RelocRva & 0xFFFFF000 ) == RelocBlock->VirtualAddress )) {

                    *RelocEntry++ = (USHORT)(( RelocArray[ RelocArrayIndex ].RelocType << 12 ) | ( RelocArray[ RelocArrayIndex ].RelocRva & 0x00000FFF ));
                    RelocDirRemaining -= sizeof( USHORT );

                    if ((( RelocArray[ RelocArrayIndex ].RelocType << 12 ) == IMAGE_REL_BASED_HIGHADJ ) &&
                        ( RelocDirRemaining > 0 )) {

                        *RelocEntry++ = RelocArray[ RelocArrayIndex ].HighAdjValue;
                        RelocDirRemaining -= sizeof( USHORT );
                        }

                    ++RelocArrayIndex;
                    }

                if (( RelocDirRemaining > 0 ) && ((ULONG_PTR)RelocEntry & 2 )) {
                    *RelocEntry++ = 0;
                    RelocDirRemaining -= sizeof( USHORT );
                    }

                RelocBlock->SizeOfBlock = (ULONG)((PUCHAR)RelocEntry - (PUCHAR)RelocFirst ) + sizeof( IMAGE_BASE_RELOCATION );
                RelocBlock = (UP_IMAGE_BASE_RELOCATION)((PUCHAR)RelocBlock + RelocBlock->SizeOfBlock );
                }

            MyVirtualFree( RelocArray );
            }
        }

    else {

        //
        //  No relocation table exists for this binary.  We can still perform
        //  this transformation for x86 images by inferring some of the
        //  relocation targets in the mapped image by scanning the image for
        //  4-byte values that are virtual addresses that fall within the
        //  mapped image range.  We start with the address of the first
        //  section, assuming no relocs occur in the image header.
        //

        if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) {

            SectionHeader       = IMAGE_FIRST_SECTION( NtHeader );
            ImageFirstSectionMa = MappedFile  + SectionHeader->PointerToRawData;
            ImageFirstSectionVa = ImageBaseVa + SectionHeader->VirtualAddress;
            ImageLastVa         = ImageBaseVa + NtHeader->OptionalHeader.SizeOfImage;

            for ( p = ImageFirstSectionMa; p < ( MappedFileEnd - 4 ); p++ ) {

                RelocTargetVa = *(UNALIGNED ULONG *) p;

                if (( RelocTargetVa >= ImageFirstSectionVa ) && ( RelocTargetVa < ImageLastVa )) {

                    //
                    //  This looks like a 32-bit VA that points within the image,
                    //  so we'll transform it to the corresponding new address.
                    //

                    *(UNALIGNED ULONG *)( HintMap + ( p - MappedFile )) |= 0x01010101;

                    RelocTargetRva = RelocTargetVa - ImageBaseVa;

                    NewRva = GetNewRvaFromRiftTable( RiftTable, RelocTargetRva );

                    if ( NewRva != RelocTargetRva ) {
                        NewVa = NewRva + ImageBaseVa;
                        *(UNALIGNED ULONG *) p = NewVa;

#ifdef TESTCODE
                        ++CountRelocChanges;
#endif // TESTCODE

                        }

                    p += 3;
                    }
                }

#ifdef TESTCODE

            printf( "\r%9d modified inferred reloc targets\n", CountRelocChanges );

#endif // TESTCODE

            }
        }
    }


VOID
TransformOldFile_PE_Exports(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID FileMappedImage,
    IN ULONG FileSize,
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_EXPORT_DIRECTORY ExportBlock;
    ULONG UNALIGNED* Entry;
    PUCHAR MappedFile;
    PUCHAR MappedFileEnd;
    ULONG  FileOffset;
    ULONG  ExportDirOff;
    ULONG  ExportDirSize;
    ULONG  EntryCount;

    MappedFile    = FileMappedImage;
    MappedFileEnd = MappedFile + FileSize;

    ExportDirOff = ImageDirectoryOffsetAndSize( NtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportDirSize );

    if (( ExportDirOff ) && (( ExportDirOff + ExportDirSize ) <= FileSize )) {

        memset( HintMap + ExportDirOff, 0x01, ExportDirSize );  // may need to be OR'd if other bits are used

        ExportBlock = (UP_IMAGE_EXPORT_DIRECTORY)( MappedFile + ExportDirOff );

        EntryCount = ExportBlock->NumberOfFunctions;
        FileOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ExportBlock->AddressOfFunctions );

        memset( HintMap + FileOffset, 0x01, EntryCount * sizeof( ULONG )); // may need to be OR'd if other bits are used

        Entry = (PULONG)( MappedFile + FileOffset );

        while ( EntryCount-- ) {
            ChangeOldRvaToNewRva( RiftTable, Entry++ );
            }

        EntryCount = ExportBlock->NumberOfNames;
        FileOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ExportBlock->AddressOfNames );

        memset( HintMap + FileOffset, 0x01, EntryCount * sizeof( ULONG )); // may need to be OR'd if other bits are used

        Entry = (PULONG)( MappedFile + FileOffset );

        while ( EntryCount-- ) {
            ChangeOldRvaToNewRva( RiftTable, Entry++ );
            }

        EntryCount = ExportBlock->NumberOfNames;
        FileOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ExportBlock->AddressOfNameOrdinals );

        memset( HintMap + FileOffset, 0x01, EntryCount * sizeof( USHORT )); // may need to be OR'd if other bits are used

        ChangeOldRvaToNewRva( RiftTable, &ExportBlock->Name );
        ChangeOldRvaToNewRva( RiftTable, &ExportBlock->AddressOfFunctions );
        ChangeOldRvaToNewRva( RiftTable, &ExportBlock->AddressOfNames );
        ChangeOldRvaToNewRva( RiftTable, &ExportBlock->AddressOfNameOrdinals );
        }

    return;
    }


VOID
TransformOldFile_PE_Imports(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID FileMappedImage,
    IN ULONG FileSize,
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_IMPORT_BY_NAME    ImportByNameData;
    UP_IMAGE_IMPORT_DESCRIPTOR ImportBlock;
    UP_IMAGE_THUNK_DATA32      ThunkDataStart;
    UP_IMAGE_THUNK_DATA32      ThunkData;
    PUCHAR MappedFile;
    PUCHAR MappedFileEnd;
    ULONG  FileOffset;
    ULONG  ImportDirOff;
    ULONG  ImportDirSize;
    ULONG  ImportByNameDataOffset;

    MappedFile    = FileMappedImage;
    MappedFileEnd = MappedFile + FileSize;

    ImportDirOff = ImageDirectoryOffsetAndSize( NtHeader, IMAGE_DIRECTORY_ENTRY_IMPORT, &ImportDirSize );

    if (( ImportDirOff ) && (( ImportDirOff + ImportDirSize ) <= FileSize )) {

        memset( HintMap + ImportDirOff, 0x01, ImportDirSize );  // may need to be OR'd if other bits are used

        ImportBlock = (UP_IMAGE_IMPORT_DESCRIPTOR)( MappedFile + ImportDirOff );

        while ( ImportBlock->OriginalFirstThunk ) {

            if ( ! ImportBlock->TimeDateStamp ) {

                FileOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ImportBlock->OriginalFirstThunk );

                ThunkData = ThunkDataStart = (UP_IMAGE_THUNK_DATA32)( MappedFile + FileOffset );

                while ( ThunkData->u1.Ordinal != 0 ) {

                    if ( ! IMAGE_SNAP_BY_ORDINAL32( ThunkData->u1.Ordinal )) {

                        ImportByNameDataOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ThunkData->u1.AddressOfData );

                        ImportByNameData = (UP_IMAGE_IMPORT_BY_NAME)( MappedFile + ImportByNameDataOffset );

                        memset( HintMap + ImportByNameDataOffset, 0x01, strlen( (LPSTR)ImportByNameData->Name ) + 3 ); // may need to be OR'd if other bits are used

                        ChangeOldRvaToNewRva( RiftTable, &ThunkData->u1.AddressOfData );
                        }

                    ThunkData++;
                    }

                memset( HintMap + FileOffset, 0x01, ((PUCHAR)ThunkData - (PUCHAR)ThunkDataStart )); // may need to be OR'd if other bits are used

                FileOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ImportBlock->FirstThunk );

                ThunkData = ThunkDataStart = (UP_IMAGE_THUNK_DATA32)( MappedFile + FileOffset );

                while ( ThunkData->u1.Ordinal != 0 ) {

                    if ( ! IMAGE_SNAP_BY_ORDINAL32( ThunkData->u1.Ordinal )) {

                        ImportByNameDataOffset = ImageRvaToFileOffset( NtHeader, (ULONG) ThunkData->u1.AddressOfData );

                        ImportByNameData = (UP_IMAGE_IMPORT_BY_NAME)( MappedFile + ImportByNameDataOffset );

                        memset( HintMap + ImportByNameDataOffset, 0x01, strlen( (LPSTR)ImportByNameData->Name ) + 3 ); // may need to be OR'd if other bits are used

                        ChangeOldRvaToNewRva( RiftTable, &ThunkData->u1.AddressOfData );
                        }

                    ThunkData++;
                    }

                memset( HintMap + FileOffset, 0x01, ((PUCHAR)ThunkData - (PUCHAR)ThunkDataStart )); // may need to be OR'd if other bits are used
                }

            ChangeOldRvaToNewRva( RiftTable, &ImportBlock->Name );
            ChangeOldRvaToNewRva( RiftTable, &ImportBlock->OriginalFirstThunk );
            ChangeOldRvaToNewRva( RiftTable, &ImportBlock->FirstThunk );

            ImportBlock++;
            }
        }

    //
    //  Another other big thing that will prevent long matches through
    //  the IMAGE_IMPORT_BY_NAME entries is the Hint values which
    //  may change (from implib for dll being imported).  The Hint
    //  values are stored between each of the names.  Maybe a separate
    //  "hint rift table" to fix those, or zero out all the hints in
    //  both the old and new files, then after the new file is built,
    //  go fill-in the hint values.
    //
    //  Currently we have no infrastructure for pre-modification of
    //  the new file before compression and post-modification after
    //  decompression.
    //

    return;
    }


#ifdef DONTCOMPILE  // jmps2 and jmps3 are experimental


VOID
TransformOldFile_PE_RelativeJmps2(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PUCHAR OldFileMapped,
    IN ULONG  OldFileSize,
    IN PUCHAR NewFileMapped,         // OPTIONAL
    IN ULONG  NewFileSize,           // OPTIONAL
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_NT_HEADERS32   NewNtHeader;
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG  SectionCount;
    PUCHAR SectionStart;
    PUCHAR SectionExtent;
    PUCHAR SearchExtent;
    ULONG  SectionLength;
    ULONG  SectionOffset;
    ULONG  SectionBaseRva;
    ULONG  SectionLastRva;
    ULONG  ImageLastRva;
    LONG   Displacement;
    LONG   NewDisplacement;
    ULONG  OffsetInSection;
    ULONG  OriginRva;
    ULONG  TargetRva;
    ULONG  NewOriginRva;
    ULONG  NewTargetRva;
    ULONG  i;
    PUCHAR p;

    //
    //  For each executable section, scan for opcodes that indicate
    //  relative call or branch instructions (different opcodes for
    //  different machine types).
    //

#ifdef TESTCODE

    ULONG CountRelativeBranchChanges = 0;
    ULONG CountRiftModifications = 0;
    ULONG CountRiftDeletions = 0;

    ULONG CountUnmatchedBranches = 0;

    ULONG CountUnmatchedE8 = 0;
    ULONG CountUnmatchedE9 = 0;
    ULONG CountUnmatched0F = 0;

    ULONG CountUnmatchedE8Targets = 0;
    ULONG CountUnmatchedE9Targets = 0;
    ULONG CountUnmatched0FTargets = 0;

    ULONG CountUnmatchedE8Followers = 0;
    ULONG CountUnmatchedE9Followers = 0;
    ULONG CountUnmatched0FFollowers = 0;

    ULONG CountUnmatchedE8Instructions = 0;
    ULONG CountUnmatchedE9Instructions = 0;
    ULONG CountUnmatched0FInstructions = 0;

    ULONG CountBranchInversions = 0;

#endif // TESTCODE

    NewNtHeader   = NewFileMapped ? GetNtHeader( NewFileMapped, NewFileSize ) : NULL;
    ImageLastRva  = NtHeader->OptionalHeader.SizeOfImage;
    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {

        if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {

            SectionBaseRva = SectionHeader[ i ].VirtualAddress;
            SectionLength  = MIN( SectionHeader[ i ].Misc.VirtualSize, SectionHeader[ i ].SizeOfRawData );
            SectionOffset  = SectionHeader[ i ].PointerToRawData;
            SectionStart   = OldFileMapped + SectionOffset;
            SectionLastRva = SectionBaseRva + SectionLength;

            if (( SectionOffset < OldFileSize ) &&
                (( SectionOffset + SectionLength ) <= OldFileSize )) {

                if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) {

                    SearchExtent = SectionStart + SectionLength - 5;

                    for ( p = SectionStart; p < SearchExtent; p++ ) {

                        if (( *p == 0xE8 ) ||       // call relative
                            ( *p == 0xE9 ) ||       // jmp relative
                            (( *p == 0x0F ) &&      // jcc relative (0F 8x)
                             (( *( p + 1 ) & 0xF0 ) == 0x80 ) &&
                             ( ++p < SearchExtent ))) {

                            //
                            //  Relative displacement is stored as
                            //  32-bit signed value following these
                            //  opcodes.  The displacement is relative
                            //  to the NEXT instruction, which is at
                            //  (p + 5).
                            //

                            Displacement = *(UNALIGNED LONG*)( p + 1 );

                            //
                            //  We expect a lot of false positives here because
                            //  occurences of <E8>, <E9>, and <0F><8x> will
                            //  likely occur in other parts of the instruction
                            //  stream so now we validate that the TargetRva
                            //  falls within the image and within an executable
                            //  section.
                            //
                            //  Also, for jmp and jcc instructions, verify that
                            //  the displacement is larger than +/- 127 because
                            //  if it wasn't, the instruction should have been
                            //  encoded as an 8-bit near branch, not a 32-bit
                            //  branch.  This prevents us from falsely matching
                            //  data that looks like:
                            //
                            //      xxE9xxxx 00000000
                            //

                            if (( *p == 0xE8 ) ||
                                ( Displacement >  127 ) ||
                                ( Displacement < -128 )) {

                                OffsetInSection = ( p + 5 ) - SectionStart;
                                OriginRva       = SectionBaseRva + OffsetInSection;
                                TargetRva       = OriginRva + Displacement;

                                if ((( TargetRva >= SectionBaseRva ) &&
                                     ( TargetRva <  SectionLastRva )) ||
                                    (( TargetRva <  ImageLastRva ) &&
                                     ( IsImageRvaInExecutableSection( NtHeader, TargetRva )))) {

                                    //
                                    //  Looks like a valid TargetRva.
                                    //


                                    NewTargetRva = GetNewRvaFromRiftTable( RiftTable, TargetRva );
                                    NewOriginRva = GetNewRvaFromRiftTable( RiftTable, OriginRva );

                                    NewDisplacement = NewTargetRva - NewOriginRva;

                                    if ( NewDisplacement != Displacement ) {
                                        *(UNALIGNED LONG*)( p + 1 ) = NewDisplacement;
#ifdef TESTCODE
                                        ++CountRelativeBranchChanges;
#endif // TESTCODE
                                        }

                                    p += 4;
                                    }
                                }
                            }
                        }
                    }

                else if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_ALPHA ) {

                    //
                    //  Need to implement the scan for Alpha platform
                    //  relative call/jmp/jcc opcodes.
                    //

                    }
                }
            }
        }

#ifdef TESTCODE

    printf( "\r%d modified relative branches\n", CountRelativeBranchChanges );
    printf( "%d rift back-coasting modifications due to branch inspection\n", CountRiftModifications );
    printf( "%d rift deletions due to branch inspection back-coasting\n", CountRiftDeletions );
    printf( "%d total unmatched relative branches, composed of:\n", CountUnmatchedBranches );

    printf( "\t%d unmatched E8 (call)\n", CountUnmatchedE8 );
    printf( "\t\t%d unmatched E8 (call) instructions\n", CountUnmatchedE8Instructions );
    printf( "\t\t%d unmatched E8 (call) followers\n", CountUnmatchedE8Followers );
    printf( "\t\t%d unmatched E8 (call) targets\n", CountUnmatchedE8Targets );

    printf( "\t%d unmatched E9 (jmp)\n",    CountUnmatchedE9 );
    printf( "\t\t%d unmatched E9 (jmp) instructions\n", CountUnmatchedE9Instructions );
    printf( "\t\t%d unmatched E9 (jmp) targets\n", CountUnmatchedE9Targets );

    printf( "\t%d unmatched 0F 8x (jcc)\n", CountUnmatched0F );
    printf( "\t\t%d unmatched 0F 8x (jcc) instructions\n", CountUnmatched0FInstructions );
    printf( "\t\t\t%d unmatched 0F 8x (jcc) instruction inversions\n", CountBranchInversions );
    printf( "\t\t%d unmatched 0F 8x (jcc) followers\n", CountUnmatched0FFollowers );
    printf( "\t\t%d unmatched 0F 8x (jcc) targets\n", CountUnmatched0FTargets );

#endif // TESTCODE

    }


#ifdef _M_IX86

__inline char * mymemchr( char *buf, int c, unsigned count ) {

    __asm {
            mov     edi, buf
            mov     ecx, count
            mov     eax, c
            repne   scasb
            lea     eax, [edi-1]
            jz      RETURNIT
            xor     eax, eax
RETURNIT:
        }
    }

#else // ! _M_IX86

#define mymemchr memchr

#endif // ! _M_IX86



VOID
TransformOldFile_PE_RelativeJmps3(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PUCHAR OldFileMapped,
    IN ULONG  OldFileSize,
    IN PUCHAR NewFileMapped,         // OPTIONAL
    IN ULONG  NewFileSize,           // OPTIONAL
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_NT_HEADERS32   NewNtHeader;
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG  SectionCount;
    PUCHAR SectionStart;
    PUCHAR SectionExtent;
    ULONG  SearchExtent;
    ULONG  SectionLength;
    ULONG  SectionOffset;
    ULONG  SectionBaseRva;
    ULONG  SectionLastRva;
    ULONG  ImageLastRva;
    LONG   DisplacementValue;
    LONG   NewDisplacement;
    LONG   OffsetToRvaAdjust;
    ULONG  FileOffset;
    ULONG  TargetOffset;
    UCHAR  Instruction;
    ULONG  InstructionLength;
    ULONG  DisplacementOrigin;
    ULONG  DisplacementOffset;
    BOOL   Skip;
    ULONG  OffsetInSection;
    ULONG  OriginRva;
    ULONG  TargetRva;
    ULONG  NewOriginRva;
    ULONG  NewTargetRva;
    ULONG  i;
    ULONG  j;
    PUCHAR p;

    //
    //  For each executable section, scan for opcodes that indicate
    //  relative call or branch instructions (different opcodes for
    //  different machine types).
    //

#ifdef TESTCODE

    ULONG CountRelativeBranchChanges = 0;
    ULONG CountRiftModifications = 0;
    ULONG CountRiftDeletions = 0;

    ULONG CountUnmatchedBranches = 0;

    ULONG CountUnmatchedE8 = 0;
    ULONG CountUnmatchedE9 = 0;
    ULONG CountUnmatched0F = 0;

    ULONG CountUnmatchedE8Targets = 0;
    ULONG CountUnmatchedE9Targets = 0;
    ULONG CountUnmatched0FTargets = 0;

    ULONG CountUnmatchedE8Followers = 0;
    ULONG CountUnmatchedE9Followers = 0;
    ULONG CountUnmatched0FFollowers = 0;

    ULONG CountUnmatchedE8Instructions = 0;
    ULONG CountUnmatchedE9Instructions = 0;
    ULONG CountUnmatched0FInstructions = 0;

    ULONG CountBranchInversions = 0;

#endif // TESTCODE

    NewNtHeader   = NewFileMapped ? GetNtHeader( NewFileMapped, NewFileSize ) : NULL;
    ImageLastRva  = NtHeader->OptionalHeader.SizeOfImage - 1;
    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {

        if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {

            SectionBaseRva = SectionHeader[ i ].VirtualAddress;
            SectionLength  = MIN( SectionHeader[ i ].Misc.VirtualSize, SectionHeader[ i ].SizeOfRawData );
            SectionOffset  = SectionHeader[ i ].PointerToRawData;
            SectionStart   = OldFileMapped + SectionOffset;
            SectionLastRva = SectionBaseRva + SectionLength;
            OffsetToRvaAdjust = SectionHeader[ i ].VirtualAddress - SectionHeader[ i ].PointerToRawData;

            if (( SectionOffset < OldFileSize ) &&
                (( SectionOffset + SectionLength ) <= OldFileSize )) {

                if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) {

                    SearchExtent = SectionOffset + SectionLength - 6;

                    for ( FileOffset = SectionOffset; FileOffset < SearchExtent; FileOffset++ ) {

                        Instruction = OldFileMapped[ FileOffset ];

                        switch ( Instruction ) {

                            case 0xE8:

                                InstructionLength  = 6;     // E8 xx xx xx xx yy
                                DisplacementOrigin = FileOffset + 5;
                                DisplacementOffset = 1;
                                break;

                            case 0xE9:

continue;

                                InstructionLength  = 5;     // E9 xx xx xx xx
                                DisplacementOrigin = FileOffset + 5;
                                DisplacementOffset = 1;
                                break;

                            case 0x0F:

continue;

                                if (( OldFileMapped[ FileOffset + 1 ] & 0xF0 ) != 0x80 ) {
                                    continue;
                                    }

                                InstructionLength  = 7;     // 0F 8x yy yy yy yy zz
                                DisplacementOrigin = FileOffset + 6;
                                DisplacementOffset = 2;
                                break;

                            default:

                                continue;

                            }

                        Skip = FALSE;

                        for ( j = 0; j < InstructionLength; j++ ) {
                            if ( HintMap[ FileOffset + j ] & 0x01 ) {
                                Skip = TRUE;
                                break;
                                }
                            }

                        if ( Skip ) {
                            continue;
                            }

                        DisplacementValue = *(UNALIGNED LONG*)( OldFileMapped + FileOffset + DisplacementOffset );

                        if (( Instruction != 0xE8 ) &&
                            (( DisplacementValue > 127 ) || ( DisplacementValue < -128 ))) {

                            continue;
                            }

                        OriginRva = DisplacementOrigin + OffsetToRvaAdjust;
                        TargetRva = OriginRva + DisplacementValue;

                        if ( TargetRva > ImageLastRva ) {
                            continue;
                            }

                        TargetOffset = ImageRvaToFileOffset( NtHeader, TargetRva );

                        if ( HintMap[ TargetOffset ] & 0x01 ) {
                            continue;
                            }


                        NewTargetRva = GetNewRvaFromRiftTable( RiftTable, TargetRva );
                        NewOriginRva = GetNewRvaFromRiftTable( RiftTable, OriginRva );

                        NewDisplacement = NewTargetRva - NewOriginRva;

                        if ( NewDisplacement != DisplacementValue ) {
                            *(UNALIGNED LONG*)( OldFileMapped + FileOffset + DisplacementOffset ) = NewDisplacement;
#ifdef TESTCODE
                            ++CountRelativeBranchChanges;
#endif // TESTCODE
                            }

                        FileOffset = DisplacementOrigin - 1;
                        }
                    }

                else if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_ALPHA ) {

                    //
                    //  Need to implement the scan for Alpha platform
                    //  relative call/jmp/jcc opcodes.
                    //

                    }
                }
            }
        }

#ifdef TESTCODE

    printf( "\r%d modified relative branches\n", CountRelativeBranchChanges );
    printf( "%d rift back-coasting modifications due to branch inspection\n", CountRiftModifications );
    printf( "%d rift deletions due to branch inspection back-coasting\n", CountRiftDeletions );
    printf( "%d total unmatched relative branches, composed of:\n", CountUnmatchedBranches );

    printf( "\t%d unmatched E8 (call)\n", CountUnmatchedE8 );
    printf( "\t\t%d unmatched E8 (call) instructions\n", CountUnmatchedE8Instructions );
    printf( "\t\t%d unmatched E8 (call) followers\n", CountUnmatchedE8Followers );
    printf( "\t\t%d unmatched E8 (call) targets\n", CountUnmatchedE8Targets );

    printf( "\t%d unmatched E9 (jmp)\n",    CountUnmatchedE9 );
    printf( "\t\t%d unmatched E9 (jmp) instructions\n", CountUnmatchedE9Instructions );
    printf( "\t\t%d unmatched E9 (jmp) targets\n", CountUnmatchedE9Targets );

    printf( "\t%d unmatched 0F 8x (jcc)\n", CountUnmatched0F );
    printf( "\t\t%d unmatched 0F 8x (jcc) instructions\n", CountUnmatched0FInstructions );
    printf( "\t\t\t%d unmatched 0F 8x (jcc) instruction inversions\n", CountBranchInversions );
    printf( "\t\t%d unmatched 0F 8x (jcc) followers\n", CountUnmatched0FFollowers );
    printf( "\t\t%d unmatched 0F 8x (jcc) targets\n", CountUnmatched0FTargets );

#endif // TESTCODE

    }


#endif // DONTCOMPILE

VOID
TransformOldFile_PE_RelativeJmps(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID FileMappedImage,
    IN ULONG FileSize,
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG  SectionCount;
    PUCHAR SectionStart;
    PUCHAR SearchExtent;
    ULONG  SectionLength;
    ULONG  SectionOffset;
    ULONG  SectionBaseRva;
    ULONG  ImageLastRva;
    LONG   Displacement;
    LONG   NewDisplacement;
    ULONG  OffsetInSection;
    ULONG  OriginRva;
    ULONG  TargetRva;
    ULONG  NewOriginRva;
    ULONG  NewTargetRva;
    ULONG  TargetOffset;
    BOOL   Skip;
    ULONG  i;
    ULONG  j;
    PUCHAR p;

    //
    //  For each executable section, scan for opcodes that indicate
    //  relative branch instructions (different opcodes for different
    //  machine types).
    //

#ifdef TESTCODE

    ULONG CountRelativeBranchChanges = 0;

#endif // TESTCODE

    ImageLastRva  = NtHeader->OptionalHeader.SizeOfImage;
    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {

        if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {

            SectionBaseRva = SectionHeader[ i ].VirtualAddress;
            SectionLength  = MIN( SectionHeader[ i ].Misc.VirtualSize, SectionHeader[ i ].SizeOfRawData );
            SectionOffset  = SectionHeader[ i ].PointerToRawData;
            SectionStart   = (PUCHAR)FileMappedImage + SectionOffset;

            if (( SectionOffset < FileSize ) &&
                (( SectionOffset + SectionLength ) <= FileSize )) {

                if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) {

                    SearchExtent = SectionStart + SectionLength - 5;

                    for ( p = SectionStart; p < SearchExtent; p++ ) {

                        if (( *p == 0xE9 ) ||       // jmp relative32 (E9)
                            (( *p == 0x0F ) &&      // jcc relative32 (0F 8x)
                             (( *( p + 1 ) & 0xF0 ) == 0x80 ) &&
                             ( ++p < SearchExtent ))) {

                            //
                            //  Validate that instruction and target are NOT
                            //  something we've already identified as something
                            //  else (reloc target, etc).
                            //

                            Skip = FALSE;

                            if (( *p & 0xF0 ) == 0x80 ) {
                                if ( HintMap[ SectionOffset + ( p - SectionStart ) - 1 ] & 0x01 ) {
                                    Skip = TRUE;
                                    }
                                }

                            if ( ! Skip ) {
                                for ( j = 0; j < 5; j++ ) {
                                    if ( HintMap[ SectionOffset + ( p - SectionStart ) + j ] & 0x01 ) {
                                        Skip = TRUE;
                                        break;
                                        }
                                    }
                                }

                            if ( ! Skip ) {

                                //
                                //  Relative displacement is stored as 32-bit
                                //  signed value following these opcodes.  The
                                //  displacement is relative to the NEXT
                                //  instruction, which is at (p + 5).
                                //
                                //  Also, for jmp and jcc instructions, verify that
                                //  the displacement is larger than +/- 127 because
                                //  if it wasn't, the instruction should have been
                                //  encoded as an 8-bit near branch, not a 32-bit
                                //  branch.  This prevents us from falsely matching
                                //  data that looks like:
                                //
                                //      xxE9xxxx 00000000
                                //

                                Displacement = *(UNALIGNED LONG*)( p + 1 );

                                if (( Displacement >  127 ) ||
                                    ( Displacement < -128 )) {

                                    OffsetInSection = (ULONG)(( p + 5 ) - SectionStart );
                                    OriginRva       = SectionBaseRva + OffsetInSection;
                                    TargetRva       = OriginRva + Displacement;

                                    //
                                    //  We expect a lot of false positives here because
                                    //  occurences of <E9>, and <0F><8x> will
                                    //  likely occur in other parts of the instruction
                                    //  stream so now we validate that the TargetRva
                                    //  falls within the image and within an executable
                                    //  section.
                                    //

                                    if ( TargetRva < ImageLastRva ) {

                                        TargetOffset = ImageRvaToFileOffset( NtHeader, TargetRva );

                                        if ( ! ( HintMap[ TargetOffset ] & 0x01 )) {

                                            //
                                            //  Looks like a valid TargetRva, so lookup its
                                            //  corresponding "new" RVA in the rift table.
                                            //

                                            NewTargetRva = GetNewRvaFromRiftTable( RiftTable, TargetRva );
                                            NewOriginRva = GetNewRvaFromRiftTable( RiftTable, OriginRva );

                                            NewDisplacement = NewTargetRva - NewOriginRva;

                                            if (( NewDisplacement >  127 ) ||
                                                ( NewDisplacement < -128 )) {

                                                if ( NewDisplacement != Displacement ) {

                                                    *(UNALIGNED LONG*)( p + 1 ) = NewDisplacement;
#ifdef TESTCODE
                                                    ++CountRelativeBranchChanges;
#endif // TESTCODE
                                                    }
                                                }

                                            else {

                                                //
                                                //  If new displacement is 8 bits, it would be
                                                //  encoded as an 8-bit relative instruction.
                                                //  For E9, instructions, that is EB.  For
                                                //  0F 8x instructions, that is 7x.  In both
                                                //  cases, we're shrinking the instruction stream.
                                                //  We'll leave the extra bytes alone.
                                                //

                                                if ( *p == 0xE9 ) {

                                                    *p = 0xEB;
                                                    *( p + 1 ) = (CHAR) NewDisplacement;
                                                    }

                                                else {

                                                    *( p - 1 ) = (UCHAR)(( *p & 0x0F ) | ( 0x70 ));
                                                    *p = (CHAR) NewDisplacement;
                                                    }

#ifdef TESTCODE
                                                ++CountRelativeBranchChanges;
#endif // TESTCODE

                                                }

                                            p += 4;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                else if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_ALPHA ) {

                    //
                    //  Need to implement the scan for Alpha platform
                    //  relative jmp/jcc opcodes.
                    //

                    }
                }
            }
        }

#ifdef TESTCODE

    printf( "\r%9d modified relative branches\n", CountRelativeBranchChanges );

#endif // TESTCODE

    }


VOID
TransformOldFile_PE_RelativeCalls(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PVOID FileMappedImage,
    IN ULONG FileSize,
    IN PRIFT_TABLE RiftTable,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG  SectionCount;
    PUCHAR SectionStart;
    PUCHAR SearchExtent;
    ULONG  SectionLength;
    ULONG  SectionOffset;
    ULONG  SectionBaseRva;
    ULONG  ImageLastRva;
    LONG   Displacement;
    LONG   NewDisplacement;
    ULONG  OffsetInSection;
    ULONG  OriginRva;
    ULONG  TargetRva;
    ULONG  NewOriginRva;
    ULONG  NewTargetRva;
    ULONG  TargetOffset;
    BOOL   Skip;
    ULONG  i;
    ULONG  j;
    PUCHAR p;

    //
    //  For each executable section, scan for opcodes that indicate
    //  relative call or branch instructions (different opcodes for
    //  different machine types).
    //

#ifdef TESTCODE

    ULONG CountRelativeCallChanges = 0;

#endif // TESTCODE

    ImageLastRva  = NtHeader->OptionalHeader.SizeOfImage;
    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {

        if ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) {

            SectionBaseRva = SectionHeader[ i ].VirtualAddress;
            SectionLength  = MIN( SectionHeader[ i ].Misc.VirtualSize, SectionHeader[ i ].SizeOfRawData );
            SectionOffset  = SectionHeader[ i ].PointerToRawData;
            SectionStart   = (PUCHAR)FileMappedImage + SectionOffset;

            if (( SectionOffset < FileSize ) &&
                (( SectionOffset + SectionLength ) <= FileSize )) {

                if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ) {

                    SearchExtent = SectionStart + SectionLength - 5;

                    for ( p = SectionStart; p < SearchExtent; p++ ) {

                        if ( *p == 0xE8 ) {         // call relative32

                            //
                            //  Validate that instruction and target are NOT
                            //  something we've already identified as something
                            //  else (reloc target, etc).
                            //

                            Skip = FALSE;

                            for ( j = 0; j < 5; j++ ) {
                                if ( HintMap[ SectionOffset + ( p - SectionStart ) + j ] & 0x01 ) {
                                    Skip = TRUE;
                                    break;
                                    }
                                }

                            if ( ! Skip ) {

                                //
                                //  Relative displacement is stored as 32-bit
                                //  signed value following these opcodes.  The
                                //  displacement is relative to the NEXT
                                //  instruction, which is at (p + 5).
                                //

                                Displacement    = *(UNALIGNED LONG*)( p + 1 );
                                OffsetInSection = (ULONG)(( p + 5 ) - SectionStart );
                                OriginRva       = SectionBaseRva + OffsetInSection;
                                TargetRva       = OriginRva + Displacement;

                                //
                                //  We expect a lot of false positives here because
                                //  occurences of <E8> will
                                //  likely occur in other parts of the instruction
                                //  stream so now we validate that the TargetRva
                                //  falls within the image and within an executable
                                //  section.
                                //

                                if ( TargetRva < ImageLastRva ) {

                                    TargetOffset = ImageRvaToFileOffset( NtHeader, TargetRva );

                                    if ( ! ( HintMap[ TargetOffset ] & 0x01 )) {

                                        //
                                        //  Looks like a valid TargetRva, so lookup its
                                        //  corresponding "new" RVA in the rift table.
                                        //

                                        NewTargetRva = GetNewRvaFromRiftTable( RiftTable, TargetRva );
                                        NewOriginRva = GetNewRvaFromRiftTable( RiftTable, OriginRva );

                                        NewDisplacement = NewTargetRva - NewOriginRva;

                                        if ( NewDisplacement != Displacement ) {

                                            *(UNALIGNED LONG*)( p + 1 ) = NewDisplacement;
#ifdef TESTCODE
                                            ++CountRelativeCallChanges;
#endif // TESTCODE
                                            }

                                        p += 4;
                                        }
                                    }
                                }
                            }
                        }
                    }

                else if ( NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_ALPHA ) {

                    //
                    //  Need to implement the scan for Alpha platform
                    //  relative call/jmp/jcc opcodes.
                    //

                    }
                }
            }
        }

#ifdef TESTCODE

    printf( "\r%9d modified relative calls\n", CountRelativeCallChanges );

#endif // TESTCODE

    }


VOID
TransformOldFile_PE_MarkNonExe(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PUCHAR OldFileMapped,
    IN ULONG  OldFileSize,
    IN PUCHAR HintMap
    )
    {
    UP_IMAGE_SECTION_HEADER SectionHeader;
    ULONG SectionCount;
    ULONG Offset;
    ULONG Size;
    ULONG Rva;
    ULONG i;

    UNREFERENCED_PARAMETER( OldFileMapped );
    UNREFERENCED_PARAMETER( OldFileSize );

    //
    //  Need to mark all non-exectuble bytes in hint map:
    //
    //      Image header
    //      All PE image directories (import, export, etc)
    //      All non-executable sections
    //      All relocation targets
    //         (a reloc target can be in the middle of an instruction, but
    //          never the first byte of an instruction)
    //
    //  If we use other bits in hint map, may need to change these
    //  memsets to bitwise OR.
    //

    memset( HintMap + 0, 0x01, NtHeader->OptionalHeader.SizeOfHeaders );

    for ( i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++ ) {

        Rva  = NtHeader->OptionalHeader.DataDirectory[ i ].VirtualAddress;
        Size = NtHeader->OptionalHeader.DataDirectory[ i ].Size;

        if (( Rva != 0 ) && ( Size != 0 )) {
            Offset = ImageRvaToFileOffset( NtHeader, Rva );
            memset( HintMap + Offset, 0x01, Size );
            }
        }

    SectionHeader = IMAGE_FIRST_SECTION( NtHeader );
    SectionCount  = NtHeader->FileHeader.NumberOfSections;

    for ( i = 0; i < SectionCount; i++ ) {
        if ( ! ( SectionHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )) {
            memset( HintMap + SectionHeader[ i ].PointerToRawData, 0x01, SectionHeader[ i ].SizeOfRawData );
            }
        }
    }


typedef struct _RES_RECURSION_CONTEXT {
    PRIFT_TABLE RiftTable;
    PUCHAR      ResBase;
    PUCHAR      ResEnd;
    ULONG       ResSize;
    ULONG       ResDone;
    ULONG       ResTime;
    ULONG       OldResRva;
    ULONG       NewResRva;
    } RES_RECURSION_CONTEXT, *PRES_RECURSION_CONTEXT;


VOID
TransformResourceRecursive(
    IN PRES_RECURSION_CONTEXT ResContext,
    IN UP_IMAGE_RESOURCE_DIRECTORY ResDir
    )
    {
    UP_IMAGE_RESOURCE_DIRECTORY_ENTRY ResEntry;
    UP_IMAGE_RESOURCE_DATA_ENTRY ResData;
    ULONG ResEntryCount;
    ULONG NewOffset;
    ULONG NewRva;

    if (((PUCHAR)ResDir + sizeof( IMAGE_RESOURCE_DIRECTORY )) < ResContext->ResEnd ) {

        ResContext->ResDone += sizeof( *ResDir );

        if ( ResContext->ResDone > ResContext->ResSize ) {
            return;
            }

        if ( ResDir->TimeDateStamp != ResContext->ResTime ) {
             ResDir->TimeDateStamp  = ResContext->ResTime;
             }

        ResEntryCount = ResDir->NumberOfNamedEntries + ResDir->NumberOfIdEntries;
        ResEntry = (UP_IMAGE_RESOURCE_DIRECTORY_ENTRY)( ResDir + 1 );

        while (( ResEntryCount > 0 ) && ((PUCHAR)ResEntry < ( ResContext->ResEnd - sizeof( *ResEntry )))) {

            if ( ResEntry->DataIsDirectory ) {

                TransformResourceRecursive(
                    ResContext,
                    (UP_IMAGE_RESOURCE_DIRECTORY)( ResContext->ResBase + ResEntry->OffsetToDirectory )
                    );
                }

            else {

                ResData = (UP_IMAGE_RESOURCE_DATA_ENTRY)( ResContext->ResBase + ResEntry->OffsetToData );

                if (((PUCHAR)ResData > ( ResContext->ResBase )) &&
                    ((PUCHAR)ResData < ( ResContext->ResEnd - sizeof( *ResData )))) {

                    ResContext->ResDone += ResData->Size;

                    if ( ResContext->ResDone > ResContext->ResSize ) {
                        return;
                        }

                    NewRva = GetNewRvaFromRiftTable( ResContext->RiftTable, ResData->OffsetToData );

                    if ( ResData->OffsetToData != NewRva ) {
                         ResData->OffsetToData  = NewRva;
                         }
                    }
                }

            NewOffset = GetNewRvaFromRiftTable( ResContext->RiftTable, ResContext->OldResRva + ResEntry->OffsetToDirectory ) - ResContext->NewResRva;

            if ( ResEntry->OffsetToDirectory != NewOffset ) {
                 ResEntry->OffsetToDirectory  = NewOffset;
                 }

            if ( ResEntry->NameIsString ) {

                NewOffset = GetNewRvaFromRiftTable( ResContext->RiftTable, ResContext->OldResRva + ResEntry->NameOffset ) - ResContext->NewResRva;

                if ( ResEntry->NameOffset != NewOffset ) {
                     ResEntry->NameOffset  = NewOffset;
                     }
                }

            ResContext->ResDone += sizeof( *ResEntry );

            if ( ResContext->ResDone > ResContext->ResSize ) {
                return;
                }

            ++ResEntry;
            --ResEntryCount;
            }
        }
    }


VOID
TransformOldFile_PE_Resources(
    IN UP_IMAGE_NT_HEADERS32 NtHeader,
    IN PUCHAR OldFileMapped,
    IN ULONG  OldFileSize,
    IN ULONG  NewFileResTime,
    IN PRIFT_TABLE RiftTable
    )
    {
    RES_RECURSION_CONTEXT ResContext;

    ResContext.ResBase = ImageDirectoryMappedAddress(
                             NtHeader,
                             IMAGE_DIRECTORY_ENTRY_RESOURCE,
                             &ResContext.ResSize,
                             OldFileMapped,
                             OldFileSize
                             );

    if ( ResContext.ResBase ) {

        ResContext.ResEnd    = ResContext.ResBase + ResContext.ResSize;
        ResContext.ResDone   = 0;
        ResContext.OldResRva = ImageDirectoryRvaAndSize( NtHeader, IMAGE_DIRECTORY_ENTRY_RESOURCE, NULL );
        ResContext.NewResRva = GetNewRvaFromRiftTable( RiftTable, ResContext.OldResRva );
        ResContext.ResTime   = NewFileResTime;
        ResContext.RiftTable = RiftTable;

        TransformResourceRecursive(
            &ResContext,
            (UP_IMAGE_RESOURCE_DIRECTORY) ResContext.ResBase
            );
        }
    }


BOOL
TransformCoffImage(
    IN     ULONG  TransformOptions,
    IN OUT UP_IMAGE_NT_HEADERS32 NtHeader,
    IN OUT PUCHAR OldFileMapped,
    IN     ULONG  OldFileSize,
    IN     ULONG  NewFileResTime,
    IN OUT PRIFT_TABLE RiftTable,
    IN OUT PUCHAR HintMap
    )
    {
    PUCHAR InternalHintMap = NULL;

    //
    //  First, zero out the rift usage array
    //

    if ( RiftTable->RiftUsageArray != NULL ) {
        ZeroMemory( RiftTable->RiftUsageArray, RiftTable->RiftEntryAlloc * sizeof( RiftTable->RiftUsageArray[ 0 ] ));
        }

    //
    //  Allocated parallel "hint" mapping the same size as the old
    //  file.  Each one of the 8 bits corresponding to each byte in
    //  the old file can be used to track information about that
    //  byte during the transformations.
    //

    if ( HintMap == NULL ) {
        InternalHintMap = MyVirtualAlloc( OldFileSize );
        HintMap = InternalHintMap;
        }

    if ( HintMap != NULL ) {

        //
        //  Apply PE image transforms (each inside try/except)
        //

        __try {
            TransformOldFile_PE_MarkNonExe( NtHeader, OldFileMapped, OldFileSize, HintMap );
            }
        __except( EXCEPTION_EXECUTE_HANDLER ) {
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_RELOCS )) {
            __try {
                TransformOldFile_PE_Relocations( NtHeader, OldFileMapped, OldFileSize, RiftTable, HintMap );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_IMPORTS )) {
            __try {
                TransformOldFile_PE_Imports( NtHeader, OldFileMapped, OldFileSize, RiftTable, HintMap );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_EXPORTS )) {
            __try {
                TransformOldFile_PE_Exports( NtHeader, OldFileMapped, OldFileSize, RiftTable, HintMap );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_RELJMPS )) {
            __try {
                TransformOldFile_PE_RelativeJmps( NtHeader, OldFileMapped, OldFileSize, RiftTable, HintMap );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_RELCALLS )) {
            __try {
                TransformOldFile_PE_RelativeCalls( NtHeader, OldFileMapped, OldFileSize, RiftTable, HintMap );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( ! ( TransformOptions & PATCH_TRANSFORM_NO_RESOURCE )) {
            __try {
                TransformOldFile_PE_Resources( NtHeader, OldFileMapped, OldFileSize, NewFileResTime, RiftTable );
                }
            __except( EXCEPTION_EXECUTE_HANDLER ) {
                }
            }

        if ( InternalHintMap != NULL ) {
            MyVirtualFree( InternalHintMap );
            }
        }

    return TRUE;
    }




/* ---- memory helpers used by the transform ---- */

PVOID __fastcall MyVirtualAlloc(ULONG Size)
{
    return VirtualAlloc(NULL, (SIZE_T)Size, MEM_COMMIT, PAGE_READWRITE);
}

VOID __fastcall MyVirtualFree(PVOID Allocation)
{
    if (Allocation)
        VirtualFree(Allocation, 0, MEM_RELEASE);
}

/*
 * PeFixPrepareSeed -- normalize and transform an old-file image in place so
 * it matches the dictionary the LZXD stream was encoded against.  riftPairs
 * holds riftCount {OldFileRva, NewFileRva} pairs; the transform only runs
 * when the patch carries a non-empty RIFT map, mirroring the reference
 * apply path.  Returns 1 if prepared, 0 if the input is not a PE image,
 * -1 on allocation failure.
 */
int PeFixPrepareSeed(
    unsigned char *buf,
    unsigned long  len,
    unsigned long  optionFlags,
    unsigned long  transformOptions,
    unsigned long  coffBase,
    unsigned long  coffTime,
    const unsigned long *riftPairs,
    unsigned long  riftCount)
{
    UP_IMAGE_NT_HEADERS32 nt;
    RIFT_TABLE rift;
    RIFT_ENTRY *entries = NULL;
    unsigned long i;

    if (!buf || !len)
        return 0;

    nt = GetNtHeader(buf, len);
    if (!nt)
        return 0;

    if (riftCount) {
        entries = (RIFT_ENTRY *)malloc(riftCount * sizeof(RIFT_ENTRY));
        if (!entries)
            return -1;
        for (i = 0; i < riftCount; ++i) {
            entries[i].OldFileRva = riftPairs[2 * i];
            entries[i].NewFileRva = riftPairs[2 * i + 1];
        }
    }

    rift.RiftEntryCount = riftCount;
    rift.RiftEntryAlloc = riftCount;
    rift.RiftEntryArray = entries;
    rift.RiftUsageArray = NULL;

    NormalizeCoffImage(nt, buf, len, optionFlags, NULL, coffBase, coffTime);

    if (riftCount) {
        if (!TransformCoffImage(transformOptions, nt, buf, len, 0,
                                &rift, NULL)) {
            free(entries);
            return -1;
        }
    }

    free(entries);
    return 1;
}
