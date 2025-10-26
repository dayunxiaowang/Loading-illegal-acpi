// AMD IOMMU IVRS表加载器 - 用于配置AMD IOMMU硬件和ACPI表
// 主要功能：加载IVRS.bin文件，配置IOMMU硬件，重新安装ACPI表，启动操作系统

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <IndustryStandard/Acpi.h>
#include <Guid/FileInfo.h>
#include <Guid/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Library/DevicePathLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/PciIo.h>

// 禁用所有打印输出
#define NO_UI 1
#if NO_UI
#undef Print
#define Print(...) do { } while (0)
#endif

// 函数声明
STATIC
VOID
ProgramIommuControlPreserveEnTimeout(
  IN EFI_PHYSICAL_ADDRESS Base
  );

// 退出引导服务时的事件回调 - 编程IOMMU控制寄存器
STATIC
VOID
EFIAPI
OnExitBootServicesIommuCtl(
  IN EFI_EVENT Event,
  IN VOID     *Context
  )
{
  EFI_PHYSICAL_ADDRESS Base = (EFI_PHYSICAL_ADDRESS)(UINTN)Context;
  if (Base != 0) {
    ProgramIommuControlPreserveEnTimeout(Base);
  }
}

// IVRS表签名定义
#define IVRS_SIGNATURE SIGNATURE_32('I','V','R','S')

STATIC
VOID
FixRsdpChecksums(
  IN OUT EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp
  );

STATIC
EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *
FindExistingRsdp(VOID);

STATIC
VOID
FixAcpiChecksum(
  IN OUT UINT8 *Table,
  IN     UINTN  Length
  );

STATIC
EFI_STATUS
AllocateAcpiReclaimBelow4G(
  IN  UINTN                 Pages,
  OUT EFI_PHYSICAL_ADDRESS *Addr
  );

STATIC
VOID
EFIAPI
OnExitBootServicesReorder(
  IN EFI_EVENT Event,
  IN VOID     *Context
  );

STATIC
EFI_STATUS
FindFirstIvhdBaseAddress(
  OUT EFI_PHYSICAL_ADDRESS *OutBase
  );

STATIC
EFI_STATUS
FindFirstIvhdInfo(
  OUT EFI_PHYSICAL_ADDRESS *OutBase,
  OUT UINT16               *OutSegment,
  OUT UINT16               *OutDeviceId
  );

STATIC
EFI_STATUS
EnableIommuPciDevice(
  IN UINT16                 Segment,
  IN UINT16                 DeviceId
  );

STATIC
EFI_STATUS
WriteIommuBinToBase(
  IN EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
  IN CHAR16                    *AppDir,
  IN EFI_PHYSICAL_ADDRESS       Base
  );

// 修补IVRS表中所有IVHD基址 - 将IVHD基址替换为新的基址
STATIC
EFI_STATUS
PatchIvrsAllIvhdBases(
  IN VOID                  *Ivrs,
  IN EFI_PHYSICAL_ADDRESS   NewBase
  )
{
  if (Ivrs == NULL || NewBase == 0) return EFI_INVALID_PARAMETER;
  EFI_ACPI_DESCRIPTION_HEADER *Hdr = (EFI_ACPI_DESCRIPTION_HEADER *)Ivrs;
  if (Hdr->Signature != IVRS_SIGNATURE || Hdr->Length < sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12) {
    return EFI_COMPROMISED_DATA;
  }
  UINT8  *base = (UINT8 *)Ivrs;
  UINT32  headerPlusIvrsExtra = (UINT32)sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12;
  UINT32  remaining = Hdr->Length - headerPlusIvrsExtra;
  UINT8  *cur = base + headerPlusIvrsExtra;
  BOOLEAN patched = FALSE;
  while (remaining >= 1) {
    UINT8 Type = cur[0];
    // 检查IVHD条目类型 (0x10, 0x11, 0x40, 0x41)
    if (Type == 0x10 || Type == 0x11 || Type == 0x40 || Type == 0x41) {
      if (remaining < 0x12) break;
      UINT16 SubLen = 0; CopyMem(&SubLen, cur + 2, sizeof(UINT16));
      if (SubLen == 0 || SubLen > remaining) break;
      // 替换基址
      CopyMem(cur + 0x08, &NewBase, sizeof(UINT64));
      patched = TRUE;
      cur += SubLen;
      remaining -= SubLen;
      continue;
    }
    // 根据条目类型确定步长
    UINTN step = 0;
    switch (Type) {
      case 0x03: // 范围开始
      case 0x04: // 范围结束
        step = 4; break;
      case 0x43: // 别名范围开始
      case 0x48: // 特殊设备
        step = 8; break;
      default: {
        if (remaining >= 4) {
          UINT16 maybeLen = 0; CopyMem(&maybeLen, cur + 2, sizeof(UINT16));
          if (maybeLen >= 4 && maybeLen <= remaining) step = maybeLen;
        }
        if (step == 0) step = 1;
      } break;
    }
    if (step > remaining) break;
    cur += step;
    remaining -= (UINT32)step;
  }
  return patched ? EFI_SUCCESS : EFI_NOT_FOUND;
}

// 在4GB以下分配ACPI回收内存
STATIC
EFI_STATUS
AllocateAcpiReclaimBelow4G(
  IN  UINTN                 Pages,
  OUT EFI_PHYSICAL_ADDRESS *Addr
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Max;

  Max    = 0xFFFFFFFFULL;
  Status = gBS->AllocatePages(AllocateMaxAddress, EfiACPIReclaimMemory, Pages, &Max);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  *Addr = Max;
  return EFI_SUCCESS;
}

// 退出引导服务时重新排序ACPI表 - 将IVRS表放在指定位置
STATIC
VOID
EFIAPI
OnExitBootServicesReorder(
  IN EFI_EVENT Event,
  IN VOID     *Context
  )
{
  EFI_PHYSICAL_ADDRESS IvrsPhys = (EFI_PHYSICAL_ADDRESS)(UINTN)Context;
  if (IvrsPhys == 0) {
    return;
  }
  EFI_ACPI_SDT_PROTOCOL   *Sdt  = NULL;
  EFI_ACPI_TABLE_PROTOCOL *Tbl  = NULL;
  if (EFI_ERROR(gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&Sdt))) return;
  if (EFI_ERROR(gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Tbl))) return;

  // 获取现有XSDT表
  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp = FindExistingRsdp();
  if (Rsdp == NULL || Rsdp->XsdtAddress == 0) return;
  EFI_ACPI_DESCRIPTION_HEADER *Xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp->XsdtAddress;
  if (Xsdt->Signature != EFI_ACPI_2_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) return;
  UINTN XCount = (Xsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT64);
  EFI_PHYSICAL_ADDRESS *XEntries = (EFI_PHYSICAL_ADDRESS *)((UINT8 *)Xsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));
  if (XCount < 20) return;

  // 映射表索引和键值
  UINTN  *KeysByIndex = AllocateZeroPool(XCount * sizeof(UINTN));
  VOID  **HdrByIndex  = AllocateZeroPool(XCount * sizeof(VOID *));
  if (!KeysByIndex || !HdrByIndex) {
    if (KeysByIndex) FreePool(KeysByIndex);
    if (HdrByIndex)  FreePool(HdrByIndex);
    return;
  }
  for (UINTN i = 0; ; i++) {
    EFI_ACPI_SDT_HEADER *Hdr;
    EFI_ACPI_TABLE_VERSION Ver;
    UINTN Key;
    if (EFI_ERROR(Sdt->GetAcpiTable(i, &Hdr, &Ver, &Key))) break;
    for (UINTN j = 0; j < XCount; j++) {
      if (Hdr == (VOID *)(UINTN)XEntries[j]) { KeysByIndex[j] = Key; HdrByIndex[j] = Hdr; break; }
    }
  }

  // 卸载索引20之后的表
  for (UINTN j = 20; j < XCount; j++) {
    if (KeysByIndex[j] != 0) {
      Tbl->UninstallAcpiTable(Tbl, KeysByIndex[j]);
    }
  }

  // 先安装IVRS表，然后按原顺序安装其他表
  UINTN NewKey;
  Tbl->InstallAcpiTable(Tbl, (VOID *)(UINTN)IvrsPhys, ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)IvrsPhys)->Length, &NewKey);
  for (UINTN j = 20; j < XCount; j++) {
    if (HdrByIndex[j] != NULL && (EFI_PHYSICAL_ADDRESS)(UINTN)HdrByIndex[j] != IvrsPhys) {
      Tbl->InstallAcpiTable(Tbl, HdrByIndex[j], ((EFI_ACPI_DESCRIPTION_HEADER *)HdrByIndex[j])->Length, &NewKey);
    }
  }

  FreePool(KeysByIndex);
  FreePool(HdrByIndex);
}

// 修复ACPI表校验和
STATIC
VOID
FixAcpiChecksum(
  IN OUT UINT8 *Table,
  IN     UINTN  Length
  )
{
  EFI_ACPI_DESCRIPTION_HEADER *Hdr = (EFI_ACPI_DESCRIPTION_HEADER *)(VOID *)Table;
  Hdr->Checksum = 0;
  UINT8 Sum = CalculateCheckSum8(Table, Length);
  Hdr->Checksum = (UINT8)(0 - Sum);
}

// 读取整个文件到内存
STATIC
EFI_STATUS
ReadEntireFile(
  IN EFI_HANDLE   DeviceHandle,
  IN CHAR16      *FilePath,
  OUT VOID      **FileBuffer,
  OUT UINTN      *FileSize
  )
{
  EFI_STATUS                         Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL   *SimpleFs;
  EFI_FILE_PROTOCOL                 *Root;
  EFI_FILE_PROTOCOL                 *File;
  EFI_FILE_INFO                     *FileInfo;
  UINTN                              InfoSize;
  VOID                              *Buffer;
  UINTN                              Size;

  *FileBuffer = NULL;
  *FileSize   = 0;

  Status = gBS->HandleProtocol(DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&SimpleFs);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = SimpleFs->OpenVolume(SimpleFs, &Root);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = Root->Open(Root, &File, FilePath, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR(Status)) {
    Root->Close(Root);
    return Status;
  }

  InfoSize = 0;
  FileInfo = NULL;
  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    File->Close(File);
    Root->Close(Root);
    return Status;
  }

  FileInfo = AllocateZeroPool(InfoSize);
  if (FileInfo == NULL) {
    File->Close(File);
    Root->Close(Root);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = File->GetInfo(File, &gEfiFileInfoGuid, &InfoSize, FileInfo);
  if (EFI_ERROR(Status)) {
    FreePool(FileInfo);
    File->Close(File);
    Root->Close(Root);
    return Status;
  }

  Size = (UINTN)FileInfo->FileSize;
  FreePool(FileInfo);

  Buffer = AllocateZeroPool(Size);
  if (Buffer == NULL) {
    File->Close(File);
    Root->Close(Root);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = File->Read(File, &Size, Buffer);
  File->Close(File);
  Root->Close(Root);
  if (EFI_ERROR(Status)) {
    FreePool(Buffer);
    return Status;
  }

  *FileBuffer = Buffer;
  *FileSize   = Size;
  return EFI_SUCCESS;
}

// 获取应用程序目录路径
STATIC
CHAR16 *
GetAppDirectoryPath(
  IN EFI_LOADED_IMAGE_PROTOCOL *LoadedImage
  )
{
  FILEPATH_DEVICE_PATH  *FilePath;
  CHAR16                *FullPath;
  CHAR16                *LastSlash;
  UINTN                  DirLen;
  CHAR16                *DirPath;

  if ((LoadedImage == NULL) || (LoadedImage->FilePath == NULL)) {
    return NULL;
  }

  FilePath = NULL;
  for (EFI_DEVICE_PATH_PROTOCOL *Node = LoadedImage->FilePath; !IsDevicePathEnd (Node); Node = NextDevicePathNode (Node)) {
    if ((DevicePathType (Node) == MEDIA_DEVICE_PATH) && (DevicePathSubType (Node) == MEDIA_FILEPATH_DP)) {
      FilePath = (FILEPATH_DEVICE_PATH *)Node;
    }
  }

  if ((FilePath == NULL) || (FilePath->PathName[0] == L'\0')) {
    return NULL;
  }

  FullPath  = FilePath->PathName;
  LastSlash = NULL;
  for (UINTN i = 0; FullPath[i] != L'\0'; i++) {
    if (FullPath[i] == L'\\') {
      LastSlash = &FullPath[i];
    }
  }
  if (LastSlash == NULL) {
    return AllocateCopyPool (sizeof (L"\\"), L"\\");
  }

  DirLen  = (UINTN)(LastSlash - FullPath + 1);
  DirPath = AllocateZeroPool ((DirLen + 1) * sizeof (CHAR16));
  if (DirPath == NULL) {
    return NULL;
  }
  CopyMem (DirPath, FullPath, DirLen * sizeof (CHAR16));
  DirPath[DirLen] = L'\0';
  return DirPath;
}

// 查找现有的RSDP表
STATIC
EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *
FindExistingRsdp(VOID)
{
  for (UINTN i = 0; i < gST->NumberOfTableEntries; i++) {
    EFI_GUID *Guid = &gST->ConfigurationTable[i].VendorGuid;
    if (CompareGuid(Guid, &gEfiAcpi20TableGuid) || CompareGuid(Guid, &gEfiAcpiTableGuid)) {
      return (EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)gST->ConfigurationTable[i].VendorTable;
    }
  }
  return NULL;
}

// 重新安装所有ACPI表，将IVRS表插入到指定位置
STATIC
EFI_STATUS
ReinstallAllWithIvrs(
  IN EFI_PHYSICAL_ADDRESS IvrsPhys,
  IN UINTN                TargetIndex
  )
{
  EFI_ACPI_SDT_PROTOCOL   *Sdt  = NULL;
  EFI_ACPI_TABLE_PROTOCOL *Tbl  = NULL;
  EFI_STATUS Status;
  Status = gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&Sdt);
  if (EFI_ERROR(Status)) return Status;
  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Tbl);
  if (EFI_ERROR(Status)) return Status;

  EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp = FindExistingRsdp();
  if (Rsdp == NULL || Rsdp->XsdtAddress == 0) return EFI_NOT_FOUND;
  EFI_ACPI_DESCRIPTION_HEADER *Xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Rsdp->XsdtAddress;
  if (Xsdt->Signature != EFI_ACPI_2_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE) return EFI_COMPROMISED_DATA;
  UINTN XCount = (Xsdt->Length - sizeof(EFI_ACPI_DESCRIPTION_HEADER)) / sizeof(UINT64);
  EFI_PHYSICAL_ADDRESS *XEntries = (EFI_PHYSICAL_ADDRESS *)((UINT8 *)Xsdt + sizeof(EFI_ACPI_DESCRIPTION_HEADER));

  VOID   **Cloned   = AllocateZeroPool((XCount + 1) * sizeof(VOID *));
  UINTN   *ClnSizes = AllocateZeroPool((XCount + 1) * sizeof(UINTN));
  UINTN   *Keys     = AllocateZeroPool(XCount * sizeof(UINTN));
  if (!Cloned || !ClnSizes || !Keys) {
    if (Cloned) FreePool(Cloned);
    if (ClnSizes) FreePool(ClnSizes);
    if (Keys) FreePool(Keys);
    return EFI_OUT_OF_RESOURCES;
  }

  for (UINTN i = 0; ; i++) {
    EFI_ACPI_SDT_HEADER *Hdr;
    EFI_ACPI_TABLE_VERSION Ver;
    UINTN Key;
    if (EFI_ERROR(Sdt->GetAcpiTable(i, &Hdr, &Ver, &Key))) break;
    for (UINTN j = 0; j < XCount; j++) {
      if (Hdr == (VOID *)(UINTN)XEntries[j]) {
        Keys[j] = Key;
        break;
      }
    }
  }

  for (UINTN j = 0; j < XCount; j++) {
    EFI_ACPI_DESCRIPTION_HEADER *Hdr = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)XEntries[j];
    if (Hdr == NULL || Hdr->Length < sizeof(EFI_ACPI_DESCRIPTION_HEADER)) {
      continue;
    }
    VOID *Copy = AllocatePool(Hdr->Length);
    if (!Copy) { Status = EFI_OUT_OF_RESOURCES; goto cleanup; }
    CopyMem(Copy, Hdr, Hdr->Length);
    Cloned[j]   = Copy;
    ClnSizes[j] = Hdr->Length;
  }

  for (UINTN j = 0; j < XCount; j++) {
    if (Keys[j] != 0) {
      Tbl->UninstallAcpiTable(Tbl, Keys[j]);
    }
  }

  if (TargetIndex > XCount) TargetIndex = XCount;
  UINTN NewKey;
  for (UINTN j = 0; j < TargetIndex; j++) {
    if (Cloned[j]) {
      Tbl->InstallAcpiTable(Tbl, Cloned[j], (UINT32)ClnSizes[j], &NewKey);
    }
  }
  if (IvrsPhys != 0) {
    Tbl->InstallAcpiTable(Tbl, (VOID *)(UINTN)IvrsPhys, ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)IvrsPhys)->Length, &NewKey);
  }
  for (UINTN j = TargetIndex; j < XCount; j++) {
    if (Cloned[j]) {
      Tbl->InstallAcpiTable(Tbl, Cloned[j], (UINT32)ClnSizes[j], &NewKey);
    }
  }
  Status = EFI_SUCCESS;

cleanup:
  for (UINTN j = 0; j < XCount; j++) {
    if (Cloned && Cloned[j]) FreePool(Cloned[j]);
  }
  if (Cloned) FreePool(Cloned);
  if (ClnSizes) FreePool(ClnSizes);
  if (Keys) FreePool(Keys);
  return Status;
}

// 修复RSDP表校验和
STATIC
VOID
FixRsdpChecksums(
  IN OUT EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp
  )
{
  UINT8 Sum;
  Rsdp->Checksum = 0;
  Sum = CalculateCheckSum8((UINT8 *)Rsdp, 20);
  Rsdp->Checksum = (UINT8)(0 - Sum);

  if (Rsdp->Revision >= EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER_REVISION) {
    Rsdp->ExtendedChecksum = 0;
    Sum = CalculateCheckSum8((UINT8 *)Rsdp, sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER));
    Rsdp->ExtendedChecksum = (UINT8)(0 - Sum);
  }
}

// 查找第一个IVHD基址
STATIC
EFI_STATUS
FindFirstIvhdBaseAddress(
  OUT EFI_PHYSICAL_ADDRESS *OutBase
  )
{
  if (OutBase == NULL) return EFI_INVALID_PARAMETER;
  *OutBase = 0;

  EFI_ACPI_SDT_PROTOCOL *Sdt = NULL;
  if (EFI_ERROR(gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&Sdt))) {
    Print(L"IVRS: SDT protocol not found\r\n");
    return EFI_NOT_FOUND;
  }
  for (UINTN i = 0; ; i++) {
    EFI_ACPI_SDT_HEADER *Hdr;
    EFI_ACPI_TABLE_VERSION Ver;
    UINTN Key;
    if (EFI_ERROR(Sdt->GetAcpiTable(i, &Hdr, &Ver, &Key))) {
      break;
    }
    if (Hdr->Signature == IVRS_SIGNATURE && Hdr->Length >= sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12) {
      Print(L"IVRS: table @%p length=%u rev=%u\r\n", Hdr, Hdr->Length, Hdr->Revision);
      UINT8 *base = (UINT8 *)Hdr;
      UINT32 headerPlusIvrsExtra = (UINT32)sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12;
      UINT32 remaining = Hdr->Length - headerPlusIvrsExtra;
      UINT8 *cur = base + headerPlusIvrsExtra;
      UINT32 scanned = 0;
      while (remaining >= 1) {
        UINT8 Type = cur[0];
        if (scanned < 32) {
          Print(L"IVRS: subentry type=0x%02x off=%u rem=%u\r\n", Type, scanned, remaining);
        }
        if (Type == 0x10 || Type == 0x11 || Type == 0x40 || Type == 0x41) {
          if (remaining < 4 + 8) break;
          UINT16 SubLen = 0; CopyMem(&SubLen, cur + 2, sizeof(UINT16));
          if (SubLen == 0 || SubLen > remaining) break;
          UINT64 BaseLe = 0;
          CopyMem(&BaseLe, cur + 0x08, sizeof(UINT64));
          *OutBase = (EFI_PHYSICAL_ADDRESS)BaseLe;
          Print(L"IVRS: IVHD base=0x%lx (sublen=%u)\r\n", (UINT64)*OutBase, SubLen);
          return EFI_SUCCESS;
        }
        UINTN step = 0;
        switch (Type) {
          case 0x03:
          case 0x04: step = 4; break;
          case 0x43:
          case 0x48: step = 8; break;
          default: {
            if (remaining >= 4) {
              UINT16 maybeLen = 0; CopyMem(&maybeLen, cur + 2, sizeof(UINT16));
              if (maybeLen >= 4 && maybeLen <= remaining) {
                step = maybeLen;
              }
            }
            if (step == 0) step = 1;
          } break;
        }
        if (step > remaining) break;
        cur += step;
        remaining -= (UINT32)step;
        scanned += (UINT32)step;
      }
    }
  }
  Print(L"IVRS: no IVHD base found\r\n");
  return EFI_NOT_FOUND;
}

// 查找第一个IVHD信息（基址、段、设备ID）
STATIC
EFI_STATUS
FindFirstIvhdInfo(
  OUT EFI_PHYSICAL_ADDRESS *OutBase,
  OUT UINT16               *OutSegment,
  OUT UINT16               *OutDeviceId
  )
{
  if (OutBase == NULL || OutSegment == NULL || OutDeviceId == NULL) return EFI_INVALID_PARAMETER;
  *OutBase = 0; *OutSegment = 0; *OutDeviceId = 0;

  EFI_ACPI_SDT_PROTOCOL *Sdt = NULL;
  if (EFI_ERROR(gBS->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&Sdt))) {
    return EFI_NOT_FOUND;
  }
  for (UINTN i = 0; ; i++) {
    EFI_ACPI_SDT_HEADER *Hdr;
    EFI_ACPI_TABLE_VERSION Ver;
    UINTN Key;
    if (EFI_ERROR(Sdt->GetAcpiTable(i, &Hdr, &Ver, &Key))) {
      break;
    }
    if (Hdr->Signature == IVRS_SIGNATURE && Hdr->Length >= sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12) {
      UINT8 *base = (UINT8 *)Hdr;
      UINT32 headerPlusIvrsExtra = (UINT32)sizeof(EFI_ACPI_DESCRIPTION_HEADER) + 12;
      UINT32 remaining = Hdr->Length - headerPlusIvrsExtra;
      UINT8 *cur = base + headerPlusIvrsExtra;
      while (remaining >= 1) {
        UINT8 Type = cur[0];
        if (Type == 0x10 || Type == 0x11 || Type == 0x40 || Type == 0x41) {
          if (remaining < 0x12) break;
          UINT16 SubLen = 0; CopyMem(&SubLen, cur + 2, sizeof(UINT16));
          if (SubLen == 0 || SubLen > remaining) break;
          UINT16 DevId = 0; CopyMem(&DevId, cur + 0x04, sizeof(UINT16));
          UINT64 BaseLe = 0; CopyMem(&BaseLe, cur + 0x08, sizeof(UINT64));
          UINT16 Seg = 0; CopyMem(&Seg, cur + 0x10, sizeof(UINT16));
          *OutBase = (EFI_PHYSICAL_ADDRESS)BaseLe;
          *OutDeviceId = DevId;
          *OutSegment = Seg;
          return EFI_SUCCESS;
        }
        UINTN step = 0;
        switch (Type) {
          case 0x03:
          case 0x04: step = 4; break;
          case 0x43:
          case 0x48: step = 8; break;
          default: {
            if (remaining >= 4) {
              UINT16 maybeLen = 0; CopyMem(&maybeLen, cur + 2, sizeof(UINT16));
              if (maybeLen >= 4 && maybeLen <= remaining) step = maybeLen;
            }
            if (step == 0) step = 1;
          } break;
        }
        if (step > remaining) break;
        cur += step;
        remaining -= (UINT32)step;
      }
    }
  }
  return EFI_NOT_FOUND;
}

// 启用IOMMU PCI设备
STATIC
EFI_STATUS
EnableIommuPciDevice(
  IN UINT16                 Segment,
  IN UINT16                 DeviceId
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *Handles = NULL; UINTN Count = 0;
  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiPciIoProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR(Status)) return Status;
  for (UINTN i = 0; i < Count; i++) {
    EFI_PCI_IO_PROTOCOL *PciIo = NULL;
    if (EFI_ERROR(gBS->HandleProtocol(Handles[i], &gEfiPciIoProtocolGuid, (VOID **)&PciIo))) continue;
    UINTN Seg, Bus, Dev, Fun;
    if (EFI_ERROR(PciIo->GetLocation(PciIo, &Seg, &Bus, &Dev, &Fun))) continue;
    if ((UINT16)Seg != Segment) continue;
    UINT32 VidDid = 0;
    PciIo->Pci.Read(PciIo, EfiPciIoWidthUint32, 0x00, 1, &VidDid);
    UINT16 Vid = (UINT16)(VidDid & 0xFFFF);
    UINT16 Did = (UINT16)(VidDid >> 16);
    if (Vid != 0x1022) continue;
    if (Did != DeviceId) continue;
    UINT64 Supports = 0, Enables = 0;
    PciIo->Attributes(PciIo, EfiPciIoAttributeOperationGet, 0, &Supports);
    Enables = EFI_PCI_DEVICE_ENABLE & Supports;
    PciIo->Attributes(PciIo, EfiPciIoAttributeOperationEnable, Enables, NULL);
    break;
  }
  if (Handles) FreePool(Handles);
  return EFI_SUCCESS;
}

// 将iommu.bin文件写入到指定基址
STATIC
EFI_STATUS
WriteIommuBinToBase(
  IN EFI_LOADED_IMAGE_PROTOCOL *LoadedImage,
  IN CHAR16                    *AppDir,
  IN EFI_PHYSICAL_ADDRESS       Base
  )
{
  if (Base == 0 || LoadedImage == NULL) return EFI_INVALID_PARAMETER;
  VOID  *Bin = NULL;
  UINTN  Sz  = 0;
  EFI_STATUS Status;
  CHAR16 *Path = NULL;
  if (AppDir != NULL) {
    UINTN Len = StrLen (AppDir) + StrLen (L"iommu.bin") + 1;
    Path = AllocateZeroPool (Len * sizeof (CHAR16));
    if (Path != NULL) {
      UnicodeSPrint (Path, Len * sizeof (CHAR16), L"%siommu.bin", AppDir);
      Status = ReadEntireFile (LoadedImage->DeviceHandle, Path, &Bin, &Sz);
      FreePool(Path); Path = NULL;
    } else {
      Status = EFI_OUT_OF_RESOURCES;
    }
  } else {
    Status = ReadEntireFile (LoadedImage->DeviceHandle, L"\\iommu.bin", &Bin, &Sz);
  }
  if (EFI_ERROR(Status) || Bin == NULL || Sz == 0) {
    return Status;
  }

  UINTN ToWrite = Sz;
  if (ToWrite > (512 * 1024)) {
    ToWrite = 512 * 1024;
  }
  volatile UINT8 *Mmio = (volatile UINT8 *)(UINTN)Base;
  for (UINTN i = 0; i < ToWrite; i++) {
    Mmio[i] = ((UINT8 *)Bin)[i];
  }
  FreePool(Bin);
  return EFI_SUCCESS;
}

// 编程IOMMU控制寄存器，保持启用状态和超时设置
STATIC
VOID
ProgramIommuControlPreserveEnTimeout(
  IN EFI_PHYSICAL_ADDRESS Base
  )
{
  const UINTN CTRL_OFF   = 0x18;
  const UINTN STATUS_OFF = 0x2020;

  volatile UINT32 *Ctrl   = (volatile UINT32 *)(UINTN)(Base + CTRL_OFF);
  volatile UINT32 *Status = (volatile UINT32 *)(UINTN)(Base + STATUS_OFF);
  UINT32 ctrlStart = *Ctrl;
  UINT32 ctrlOld   = ctrlStart;
  UINT32 sts = *Status;

  const UINT32 BIT_IOMMU_EN   = (1u << 0);
  const UINT32 BITS_INV_TMO   = (7u << 5);
  const UINT32 BIT_COHERENT   = (1u << 10);
  const UINT32 BIT_CMD_EN     = (1u << 12);
  const UINT32 BIT_PPR_LOG_EN = (1u << 13);
  const UINT32 BIT_EVT_LOG_EN = (1u << 2);

  const UINT32 STS_CMD_RUN = (1u << 0);
  const UINT32 STS_EVT_RUN = (1u << 1);
  const UINT32 STS_PPR_RUN = (1u << 4);

  if (sts & STS_CMD_RUN) {
    UINT32 tmp = ctrlOld & ~BIT_CMD_EN;
    *Ctrl = tmp; MemoryFence();
    for (UINTN i = 0; i < 500; i++) {
      if ( ((*Status) & STS_CMD_RUN) == 0 ) break;
      gBS->Stall(100);
    }
    ctrlOld = *Ctrl; sts = *Status;
  }
  if (sts & STS_EVT_RUN) {
    UINT32 tmp = ctrlOld & ~BIT_EVT_LOG_EN;
    *Ctrl = tmp; MemoryFence();
    for (UINTN i = 0; i < 500; i++) {
      if ( ((*Status) & STS_EVT_RUN) == 0 ) break;
      gBS->Stall(100);
    }
    ctrlOld = *Ctrl; sts = *Status;
  }
  if (sts & STS_PPR_RUN) {
    UINT32 tmp = ctrlOld & ~BIT_PPR_LOG_EN;
    *Ctrl = tmp; MemoryFence();
    for (UINTN i = 0; i < 500; i++) {
      if ( ((*Status) & STS_PPR_RUN) == 0 ) break;
      gBS->Stall(100);
    }
    ctrlOld = *Ctrl; sts = *Status;
  }

  if (ctrlOld & BIT_IOMMU_EN) {
    UINT32 tmp = ctrlOld & ~BIT_IOMMU_EN;
    *Ctrl = tmp; MemoryFence();
    gBS->Stall(2000);
    ctrlOld = *Ctrl;
  }

  UINT32 keepMask = BIT_IOMMU_EN | BITS_INV_TMO | BIT_COHERENT;
  UINT32 desired  = ctrlStart & keepMask;
  UINT32 newVal   = (ctrlOld & ~keepMask) | desired;
  if (newVal != ctrlOld) {
    *Ctrl = newVal; MemoryFence();
  }
}

// 主函数 - AMD IOMMU IVRS表加载器入口点
EFI_STATUS
EFIAPI
UefiMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS                   Status;
  EFI_ACPI_TABLE_PROTOCOL     *AcpiTableProtocol;
  EFI_LOADED_IMAGE_PROTOCOL   *LoadedImage = NULL;
  VOID                        *Buffer;
  UINTN                        Size;
  EFI_ACPI_DESCRIPTION_HEADER *Hdr;
  EFI_HANDLE                  *Handles;
  UINTN                        HandleCount;
  UINTN                        Index;
  EFI_DEVICE_PATH_PROTOCOL    *DevicePath;
  EFI_HANDLE                   NextImage;
  CHAR16                      *AppDir;
  CHAR16                      *PathBuf;

  Print(L"");
  
  // 初始化变量
  Buffer = NULL;
  Size   = 0;

  // 获取加载的镜像协议
  Status = gBS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
  if (EFI_ERROR(Status)) {
    Print(L"LoadIvrs: Failed to get LoadedImage: %r\r\n", Status);
    return Status;
  }

  AppDir = GetAppDirectoryPath (LoadedImage);
  PathBuf = NULL;

  // 检查是否已存在IVRS表，如果存在则启用IOMMU设备
  {
    EFI_PHYSICAL_ADDRESS ExBase = 0;
    UINT16 ExSeg = 0, ExDid = 0;
    if (!EFI_ERROR(FindFirstIvhdInfo(&ExBase, &ExSeg, &ExDid)) && ExBase != 0) {
      EnableIommuPciDevice(ExSeg, ExDid);
      // 在退出引导服务时编程IOMMU控制寄存器
      EFI_EVENT Evt;
      if (!EFI_ERROR(gBS->CreateEvent(EVT_SIGNAL_EXIT_BOOT_SERVICES, TPL_CALLBACK, OnExitBootServicesIommuCtl, (VOID *)(UINTN)ExBase, &Evt))) {
      }
    }
  }

  // 读取IVRS.bin文件
  if (AppDir != NULL) {
    UINTN Len = StrLen (AppDir) + StrLen (L"IVRS.bin") + 1;
    PathBuf = AllocateZeroPool (Len * sizeof (CHAR16));
    if (PathBuf != NULL) {
      UnicodeSPrint (PathBuf, Len * sizeof (CHAR16), L"%sIVRS.bin", AppDir);
      Status = ReadEntireFile (LoadedImage->DeviceHandle, PathBuf, &Buffer, &Size);
      FreePool (PathBuf); PathBuf = NULL;
    } else {
      Status = EFI_OUT_OF_RESOURCES;
    }
  } else {
    Status = ReadEntireFile (LoadedImage->DeviceHandle, L"\\IVRS.bin", &Buffer, &Size);
  }
  if (EFI_ERROR(Status)) {
    Print(L"LoadIvrs: IVRS.bin not found: %r\r\n", Status);
    if (AppDir) FreePool(AppDir);
    return Status;
  }

  // 验证文件大小和ACPI表头
  if (Size < sizeof(EFI_ACPI_DESCRIPTION_HEADER)) {
    Print(L"LoadIvrs: File too small for ACPI header (%u bytes)\r\n", (UINT32)Size);
    if (AppDir) FreePool(AppDir);
    FreePool(Buffer);
    return EFI_LOAD_ERROR;
  }

  Hdr = (EFI_ACPI_DESCRIPTION_HEADER *)Buffer;
  if (Hdr->Signature != IVRS_SIGNATURE) {
    Print(L"LoadIvrs: Invalid signature. Expected IVRS, got 0x%08x\r\n", (UINT32)Hdr->Signature);
    if (AppDir) FreePool(AppDir);
    FreePool(Buffer);
    return EFI_COMPROMISED_DATA;
  }
  if (Hdr->Length > Size) {
    Print(L"LoadIvrs: Header length %u exceeds file size %u\r\n", Hdr->Length, (UINT32)Size);
    if (AppDir) FreePool(AppDir);
    FreePool(Buffer);
    return EFI_BAD_BUFFER_SIZE;
  }
  // 修复ACPI表校验和
  FixAcpiChecksum((UINT8 *)Buffer, Hdr->Length);

  // 确保ACPI表协议可用，如果不可用则加载AcpiTableDxe.efi驱动
  Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTableProtocol);
  if (EFI_ERROR(Status)) {
    EFI_DEVICE_PATH_PROTOCOL *AcpiDxePath = NULL;
    EFI_HANDLE                AcpiDxeImage = NULL;
    if (AppDir != NULL) {
      UINTN Len3 = StrLen (AppDir) + StrLen (L"AcpiTableDxe.efi") + 1;
      PathBuf = AllocateZeroPool (Len3 * sizeof (CHAR16));
      if (PathBuf != NULL) {
        UnicodeSPrint (PathBuf, Len3 * sizeof (CHAR16), L"%sAcpiTableDxe.efi", AppDir);
        AcpiDxePath = FileDevicePath (LoadedImage->DeviceHandle, PathBuf);
        FreePool(PathBuf); PathBuf = NULL;
      }
    } else {
      AcpiDxePath = FileDevicePath (LoadedImage->DeviceHandle, L"\\AcpiTableDxe.efi");
    }
    if (AcpiDxePath != NULL) {
      EFI_STATUS LoadSt;
      Print(L"LoadIvrs: ACPI Table Protocol missing (%r). Loading AcpiTableDxe.efi...\r\n", Status);
      LoadSt = gBS->LoadImage(FALSE, ImageHandle, AcpiDxePath, NULL, 0, &AcpiDxeImage);
      if (!EFI_ERROR(LoadSt)) {
        LoadSt = gBS->StartImage(AcpiDxeImage, NULL, NULL);
        if (EFI_ERROR(LoadSt)) {
          Print(L"LoadIvrs: Failed to start AcpiTableDxe.efi: %r\r\n", LoadSt);
        }
      } else {
        Print(L"LoadIvrs: Failed to load AcpiTableDxe.efi: %r\r\n", LoadSt);
      }
    }
    Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTableProtocol);
    if (EFI_ERROR(Status)) {
      Print(L"LoadIvrs: ACPI Table Protocol still unavailable: %r\r\n", Status);
      if (AppDir) FreePool(AppDir);
      FreePool(Buffer);
      return Status;
    }
  }

  // 在4GB以下分配ACPI回收内存并复制IVRS表
  EFI_PHYSICAL_ADDRESS IvrsPhys = 0;
  Status = AllocateAcpiReclaimBelow4G(EFI_SIZE_TO_PAGES(Hdr->Length), &IvrsPhys);
  if (EFI_ERROR(Status) || IvrsPhys == 0) {
    Print(L"LoadIvrs: Failed to allocate IVRS: %r\r\n", Status);
    if (AppDir) FreePool(AppDir);
    FreePool(Buffer);
    return Status;
  }
  CopyMem((VOID *)(UINTN)IvrsPhys, Buffer, Hdr->Length);
  FixAcpiChecksum ((UINT8 *)(UINTN)IvrsPhys, ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)IvrsPhys)->Length);
  FreePool(Buffer); Buffer = NULL;
  
  // 分配512KB实验区域并修补IVRS表中的IVHD基址
  EFI_PHYSICAL_ADDRESS FakeBase = 0;
  EFI_STATUS FbSt = gBS->AllocatePages(AllocateAnyPages, EfiACPIMemoryNVS, EFI_SIZE_TO_PAGES(512 * 1024), &FakeBase);
  if (!EFI_ERROR(FbSt)) {
    SetMem((VOID *)(UINTN)FakeBase, 512 * 1024, 0);
    EFI_STATUS Ps = PatchIvrsAllIvhdBases((VOID *)(UINTN)IvrsPhys, FakeBase);
    if (!EFI_ERROR(Ps)) {
      FixAcpiChecksum((UINT8 *)(UINTN)IvrsPhys, ((EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)IvrsPhys)->Length);
      // 将iommu.bin写入到512KB假基址区域
      WriteIommuBinToBase(LoadedImage, AppDir, FakeBase);
    }
  }

  // 重新安装所有ACPI表，将IVRS表插入到索引20位置
  Status = ReinstallAllWithIvrs(IvrsPhys, 20);
  if (EFI_ERROR(Status)) {
    Print(L"LoadIvrs: ReinstallAllWithIvrs failed: %r\r\n", Status);
    
    if (AppDir) FreePool(AppDir);
    return Status;
  }
  
  // 配置IOMMU硬件
  Print(L"");
  EFI_PHYSICAL_ADDRESS IvhdBase = 0;
  UINT16 IvhdSeg = 0, IvhdDid = 0;
  if (!EFI_ERROR(FindFirstIvhdInfo(&IvhdBase, &IvhdSeg, &IvhdDid)) && IvhdBase != 0) {
    CHAR16 Buf[96];
    UnicodeSPrint(Buf, sizeof(Buf), L"IVHD Base=0x%lx Seg=%u DevId=0x%04x", (UINT64)IvhdBase, IvhdSeg, IvhdDid);
    
    // 启用IOMMU PCI设备并编程控制寄存器
    EnableIommuPciDevice(IvhdSeg, IvhdDid);
    ProgramIommuControlPreserveEnTimeout(IvhdBase);
    // 将iommu.bin写入到IVHD基址
    EFI_STATUS Ws = WriteIommuBinToBase(LoadedImage, AppDir, IvhdBase);
    CHAR16 Buf2[64];
    UnicodeSPrint(Buf2, sizeof(Buf2), L"Write iommu.bin status: %r", Ws);
    
  } else {
    
  }
  
  // 清理资源
  if (AppDir != NULL) { FreePool (AppDir); }

  // 链式加载下一个操作系统引导加载器
  NextImage   = NULL;
  DevicePath  = NULL;
  Handles     = NULL;
  HandleCount = 0;

  Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
  if (!EFI_ERROR(Status)) {
    for (Index = 0; Index < HandleCount; Index++) {
      EFI_HANDLE                    FsHandle;
      EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs;
      EFI_FILE_PROTOCOL             *Root;
      EFI_FILE_PROTOCOL             *TestFile;

      FsHandle = Handles[Index];
      if (FsHandle == LoadedImage->DeviceHandle) {
        continue;
      }

      Fs = NULL;
      Root = NULL;
      TestFile = NULL;
      if (EFI_ERROR(gBS->HandleProtocol(FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs))) {
        continue;
      }
      if (EFI_ERROR(Fs->OpenVolume(Fs, &Root))) {
        continue;
      }

      // 查找Windows引导管理器或UEFI引导加载器
      if (!EFI_ERROR(Root->Open(Root, &TestFile, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", EFI_FILE_MODE_READ, 0))) {
        TestFile->Close(TestFile);
        Root->Close(Root);
        DevicePath = FileDevicePath(FsHandle, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
      } else if (!EFI_ERROR(Root->Open(Root, &TestFile, L"\\EFI\\Boot\\bootx64.efi", EFI_FILE_MODE_READ, 0))) {
        TestFile->Close(TestFile);
        Root->Close(Root);
        DevicePath = FileDevicePath(FsHandle, L"\\EFI\\Boot\\bootx64.efi");
      } else {
        Root->Close(Root);
        continue;
      }

      // 加载并启动下一个引导加载器
      if (DevicePath != NULL) {
        Status = gBS->LoadImage(FALSE, ImageHandle, DevicePath, NULL, 0, &NextImage);
        if (!EFI_ERROR(Status)) {
          UINTN  ExitDataSize = 0;
          CHAR16 *ExitData     = NULL;
          Print(L"LoadIvrs: Chainloading next image...\r\n");
          Status = gBS->StartImage(NextImage, &ExitDataSize, &ExitData);
          if (ExitData != NULL) {
            gBS->FreePool(ExitData);
          }
        }
        break;
      }
    }
    if (Handles != NULL) {
      FreePool(Handles);
    }
  }

  return Status;
}