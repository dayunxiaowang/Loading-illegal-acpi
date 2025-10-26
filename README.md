# Loading-illegal-acpi
通过加载非法acpi表来逃避某些反作弊要求开启iommu
Evading certain anti cheating requirements by loading illegal acpi tables to enable iommu
该项目基于edk2制作
This project is based on edk2 production
该项目被证明曾经对于ACE来说是有效的，目前会被ACE所发现
This project has been proven to be effective for ACE and will now be discovered by ACE
你需要准备的东西有edk2 2025以后的版本 ivrs.bin iommu.bin
The things you need to prepare include edk2 2025 and later versions ivrs.bin iommu.bin
该项目实现逻辑：检测ivrs表是否存在，若存在，则强行修改寄存器（该行为被确定为是危险的，同时无法正确修改寄存器，会出现两种情况，要么无法加载进入os，要么进入os后iommu无法初始化），若ivrs不存在，则加载自行准备的ivrs.bin，在加载过程中，会修改ivrs表的iommu基址，使其在一块rw memory中生效，然后会重新计算其校验和。
加载过程中 会卸载xsdt表中条目20（因为我的ivrs表在这里）以后的所有acpi表，然后优先安装ivrs表，再安装其他表，这样会使得ivrs表在整体apci表结构中更加合理。在引导结束前会将iommu.bin的内容注入到iommu基址中，伪造虚假的寄存器。
The implementation logic of this project is to check whether the ivrs table exists. If it exists, the register will be forcibly modified (this behavior is determined to be dangerous, and the register cannot be modified correctly, resulting in two situations: either unable to load into OS, or unable to initialize the iommu after entering OS). If ivrs does not exist, the self prepared ivrs.bin will be loaded. During the loading process, the iommu base address of the ivrs table will be modified to take effect in a block of RW memory, and then its checksum will be recalculated.
During the loading process, all ACPI tables after entry 20 in the XSDT table (because my IVRS table is here) will be unloaded, and then the IVRS table will be installed first, followed by other tables. This will make the IVRS table more reasonable in the overall APCI table structure. Before the boot ends, the contents of iommu.bin will be injected into the iommu base address to forge false registers.
edk2来源：github clone ivrs.bin来源：dump自己电脑的ivrs表 iommu.bin来源:dump自己电脑iommu基址的所有memory
Edk2 source: GitHub clone ivrs.bin source: dump your own computer's ivrs table iommu.bin source: dump all memory of your own computer's iommu base address
关于开源此项目的目的，因为该漏洞被证明是过时的，但是我看见intel平台上有的人使用我类似的方法，还能继续使用该漏洞，可以自行修改我的项目测试，同时也希望能在我的项目基础上开发出更多功能————Dr.chen。
The purpose of open sourcing this project is because the vulnerability has been proven to be outdated, but I have seen some people on the Intel platform using a similar method to mine and can continue to use the vulnerability. They can modify my project for testing and also hope to develop more features based on my project - Dr. Chen.
