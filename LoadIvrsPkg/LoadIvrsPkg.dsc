[Defines]
  DSC_SPECIFICATION                = 0x00010019
  PLATFORM_NAME                    = LoadIvrsPkg
  PLATFORM_GUID                    = 9f2a1a44-6d1a-4a9b-9921-3e93c6c1a7d3
  PLATFORM_VERSION                 = 0.1
  SKUID_IDENTIFIER                 = DEFAULT
  SUPPORTED_ARCHITECTURES          = IA32|X64
  BUILD_TARGETS                    = DEBUG|RELEASE
  OUTPUT_DIRECTORY                 = Build/LoadIvrsPkg

[LibraryClasses]
  UefiApplicationEntryPoint        | MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf
  UefiDriverEntryPoint             | MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  HobLib                           | MdePkg/Library/DxeHobLib/DxeHobLib.inf
  StackCheckLib                    | MdePkg/Library/StackCheckLib/StackCheckLib.inf
  StackCheckFailureHookLib         | MdePkg/Library/StackCheckFailureHookLibNull/StackCheckFailureHookLibNull.inf
  UefiLib                          | MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib         | MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib      | MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib                    | MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  BaseMemoryLib                    | MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  MemoryAllocationLib              | MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  BaseLib                          | MdePkg/Library/BaseLib/BaseLib.inf
  RegisterFilterLib                | MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  PrintLib                         | MdePkg/Library/BasePrintLib/BasePrintLib.inf
  DebugLib                         | MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  DebugPrintErrorLevelLib          | MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PcdLib                           | MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf

[Packages]
  MdePkg/MdePkg.dec
  LoadIvrsPkg/LoadIvrsPkg.dec

[Components]
  LoadIvrsPkg/Applications/LoadIvrs/LoadIvrs.inf
  MdeModulePkg/Universal/Acpi/AcpiTableDxe/AcpiTableDxe.inf


