// pe_builder_pointer.cpp
#include "windows.h"
#include <iostream>
#include <fstream>
#include <vector>
#include "./ShellcodeToPE.h"



void set_image_dos_header(IMAGE_DOS_HEADER* header, LONG elfanew_offset) {
    header->e_magic = IMAGE_DOS_SIGNATURE; // 'MZ'
    header->e_cblp = 0x0090;
    header->e_cp = 0x0003;
    header->e_crlc = 0x0000;
    header->e_cparhdr = 0x0004;
    header->e_minalloc = 0x0000;
    header->e_maxalloc = 0xFFFF;
    header->e_ss = 0x0000;
    header->e_sp = 0x00B8;
    header->e_csum = 0x0000;
    header->e_ip = 0x0000;
    header->e_cs = 0x0000;
    header->e_lfarlc = 0x0040;
    header->e_ovno = 0x0000;
    std::memset(header->e_res, 0, sizeof(header->e_res));
    header->e_oemid = 0x0000;
    header->e_oeminfo = 0x0000;
    std::memset(header->e_res2, 0, sizeof(header->e_res2));
    header->e_lfanew = elfanew_offset;
}

void set_image_dos_stub(PVOID stub) {
    const char dos_msg[] = "This program cannot be run in DOS mode.\r\n$";
    std::memcpy(stub, dos_msg, min(DOS_STUB_SIZE, sizeof(dos_msg)));
}

void set_image_file_header(IMAGE_FILE_HEADER* header, WORD num_of_sections, bool is_64) {
    if (is_64) {
        header->Machine = IMAGE_FILE_MACHINE_AMD64;
        header->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    }
    else {
        header->Machine = IMAGE_FILE_MACHINE_I386;
        header->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    }
    header->NumberOfSections = num_of_sections;
    header->TimeDateStamp = 0;
    header->PointerToSymbolTable = 0;
    header->NumberOfSymbols = 0;
    header->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
}

void set_image_data_directory(IMAGE_DATA_DIRECTORY* dir) {
    dir->VirtualAddress = 0;
    dir->Size = 0;
}

void set_image_optional_header64(IMAGE_OPTIONAL_HEADER64* header,
    DWORD code_size,
    DWORD address_of_entry_point,
    DWORD size_of_image) {
    header->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    header->MajorLinkerVersion = 14;
    header->MinorLinkerVersion = 16;
    header->SizeOfCode = code_size;
    header->SizeOfInitializedData = 0;
    header->SizeOfUninitializedData = 0;
    header->AddressOfEntryPoint = address_of_entry_point;
    header->BaseOfCode = 0x1000;
    header->ImageBase = IMAGE_BASE_X64;
    header->SectionAlignment = SECTION_ALIGNMENT;
    header->FileAlignment = FILE_ALIGNMENT;
    header->MajorOperatingSystemVersion = 6;
    header->MinorOperatingSystemVersion = 0;
    header->MajorImageVersion = 0;
    header->MinorImageVersion = 0;
    header->MajorSubsystemVersion = MAJOR_SUBSYSTEM_VERSION;
    header->MinorSubsystemVersion = 0;
    header->Win32VersionValue = 0;
    header->SizeOfImage = size_of_image;
    header->SizeOfHeaders = 0x400;
    header->CheckSum = 0;
    header->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    header->DllCharacteristics = 0x8100;
    header->SizeOfStackReserve = 0x100000;
    header->SizeOfStackCommit = 0x1000;
    header->SizeOfHeapReserve = 0x100000;
    header->SizeOfHeapCommit = 0x1000;
    header->LoaderFlags = 0;
    header->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // Initialize all data directories to empty
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        set_image_data_directory(&header->DataDirectory[i]);
    }
}

void set_image_optional_header32(IMAGE_OPTIONAL_HEADER32* header,
    DWORD code_size,
    DWORD address_of_entry_point,
    DWORD size_of_image) {
    header->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    header->MajorLinkerVersion = 14;
    header->MinorLinkerVersion = 16;
    header->SizeOfCode = code_size;
    header->SizeOfInitializedData = 0;
    header->SizeOfUninitializedData = 0;
    header->AddressOfEntryPoint = address_of_entry_point;
    header->BaseOfCode = 0x1000;
    header->BaseOfData = 0x2000;
    header->ImageBase = IMAGE_BASE_X86;
    header->SectionAlignment = SECTION_ALIGNMENT;
    header->FileAlignment = FILE_ALIGNMENT;
    header->MajorOperatingSystemVersion = 6;
    header->MinorOperatingSystemVersion = 0;
    header->MajorImageVersion = 0;
    header->MinorImageVersion = 0;
    header->MajorSubsystemVersion = MAJOR_SUBSYSTEM_VERSION;
    header->MinorSubsystemVersion = 0;
    header->Win32VersionValue = 0;
    header->SizeOfImage = size_of_image;
    header->SizeOfHeaders = 0x400;
    header->CheckSum = 0;
    header->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    header->DllCharacteristics = 0x8100;
    header->SizeOfStackReserve = 0x100000;
    header->SizeOfStackCommit = 0x1000;
    header->SizeOfHeapReserve = 0x100000;
    header->SizeOfHeapCommit = 0x1000;
    header->LoaderFlags = 0;
    header->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    // Initialize all data directories to empty
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        set_image_data_directory(&header->DataDirectory[i]);
    }
}

void set_image_nt_headers64(IMAGE_NT_HEADERS64* nt_headers,
    WORD num_of_sections,
    DWORD code_size,
    DWORD address_of_entry_point,
    DWORD size_of_image) {
    nt_headers->Signature = SIGNATURE;
    set_image_file_header(&nt_headers->FileHeader, num_of_sections, true);
    set_image_optional_header64(&nt_headers->OptionalHeader,
        code_size,
        address_of_entry_point,
        size_of_image);
}

void set_image_nt_headers32(IMAGE_NT_HEADERS32* nt_headers,
    WORD num_of_sections,
    DWORD code_size,
    DWORD address_of_entry_point,
    DWORD size_of_image) {
    nt_headers->Signature = SIGNATURE;
    set_image_file_header(&nt_headers->FileHeader, num_of_sections, false);
    set_image_optional_header32(&nt_headers->OptionalHeader,
        code_size,
        address_of_entry_point,
        size_of_image);
}

void set_image_section_header(IMAGE_SECTION_HEADER* header,
    const char* section,
    DWORD virtual_size,
    DWORD virtual_address,
    DWORD size_of_raw_data,
    DWORD pointer_to_raw_data,
    DWORD characteristics) {
    std::memset(header->Name, 0, IMAGE_SIZEOF_SHORT_NAME);
    size_t len = min(strlen(section), (size_t)IMAGE_SIZEOF_SHORT_NAME);
    std::memcpy(header->Name, section, len);
    header->Misc.VirtualSize = virtual_size;
    header->VirtualAddress = virtual_address;
    header->SizeOfRawData = size_of_raw_data;
    header->PointerToRawData = pointer_to_raw_data;
    header->PointerToRelocations = 0;
    header->PointerToLinenumbers = 0;
    header->NumberOfRelocations = 0;
    header->NumberOfLinenumbers = 0;
    header->Characteristics = characteristics;
}

// Converts shellcode into a PE executable (x86 or x64 based on is_64)
std::vector<unsigned char> shellcode_to_exe(const char* shellcode, size_t shellcode_size, bool is_64) {
    const size_t dos_hdr_size = sizeof(IMAGE_DOS_HEADER);
    const size_t nt_hdrs_size = is_64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
    const size_t section_hdr_size = sizeof(IMAGE_SECTION_HEADER);
    const size_t headers_size = 0x400; // SizeOfHeaders is typically 0x400

    DWORD section_alignment = SECTION_ALIGNMENT;
    DWORD size_of_image = section_alignment + ((DWORD)shellcode_size + section_alignment - 1) / section_alignment * section_alignment;

    size_t buf_size = headers_size + shellcode_size;
    std::vector<unsigned char> buf(buf_size, 0);

    // Set IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER dos_header = {};
    set_image_dos_header(&dos_header, static_cast<LONG>(dos_hdr_size + DOS_STUB_SIZE));
    std::memcpy(buf.data(), &dos_header, dos_hdr_size);

    set_image_dos_stub(buf.data() + dos_hdr_size);

    if (is_64) {
        // Set IMAGE_NT_HEADERS64
        IMAGE_NT_HEADERS64 nt_headers = {};
        set_image_nt_headers64(&nt_headers, 1, (DWORD)shellcode_size, 0x1000, size_of_image);
        std::memcpy(buf.data() + dos_header.e_lfanew, &nt_headers, nt_hdrs_size);
    }
    else {
        // Set IMAGE_NT_HEADERS32
        IMAGE_NT_HEADERS32 nt_headers = {};
        set_image_nt_headers32(&nt_headers, 1, (DWORD)shellcode_size, 0x1000, size_of_image);
        std::memcpy(buf.data() + dos_header.e_lfanew, &nt_headers, nt_hdrs_size);
    }

    // Set IMAGE_SECTION_HEADER
    IMAGE_SECTION_HEADER section_header = {};
    set_image_section_header(&section_header, ".text", (DWORD)shellcode_size, 0x1000, (DWORD)shellcode_size, (DWORD)headers_size, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE);
    std::memcpy(buf.data() + dos_header.e_lfanew + nt_hdrs_size, &section_header, sizeof(section_header));

    // Copy shellcode to buffer
    std::memcpy(buf.data() + headers_size, shellcode, shellcode_size);

    return buf;
}

bool parse_arguments(int argc, char* argv[], std::string& output_file, std::string& shellcode_file, bool& is_64) {
    output_file = "output.exe";
    is_64 = true; // Default to x64

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
        else if (strcmp(argv[i], "-shellcode") == 0 && i + 1 < argc) {
            shellcode_file = argv[++i];
        }
        else if (strcmp(argv[i], "-arch") == 0 && i + 1 < argc) {
            std::string arch_str = argv[++i];
            if (arch_str == "x86") {
                is_64 = false;
            }
            else if (arch_str != "x64") {
                std::cerr << "Invalid architecture specified. Use 'x86' or 'x64'.\n";
                return false;
            }
        }
    }

    return !shellcode_file.empty();
}

int main(int argc, char* argv[]) {
    std::string output_path;
    std::string shellcode_path;
    bool is_64;

    if (!parse_arguments(argc, argv, output_path, shellcode_path, is_64)) {
        std::cerr << "Usage: " << argv[0] << " -out <output_file> -shellcode <shellcode_file_path> -arch <x86|x64>\n";
        return 1;
    }

    std::cout << "Arguments parsed successfully:\n";
    std::cout << "Output path: " << output_path << "\n";
    std::cout << "Shellcode path: " << shellcode_path << "\n";
    std::cout << "Architecture: " << (is_64 ? "x64" : "x86") << "\n";

    std::ifstream shellcode_file(shellcode_path, std::ios::binary | std::ios::ate);
    if (!shellcode_file) {
        std::cerr << "Error opening shellcode file: " << shellcode_path << "\n";
        return 1;
    }

    size_t size = shellcode_file.tellg();
    shellcode_file.seekg(0, std::ios::beg);

    std::vector<unsigned char> shellcode(size);
    if (!shellcode_file.read(reinterpret_cast<char*>(shellcode.data()), size)) {
        std::cerr << "Failed to read shellcode from file\n";
        return 1;
    }

    shellcode_file.close();
    std::cout << "Shellcode read successfully from file.\n";

    size_t shellcode_size = shellcode.size();
    std::cout << "Shellcode size: " << shellcode_size << " bytes\n";

    std::cout << "Converting shellcode to executable format...\n";
    std::vector<unsigned char> exe_data = shellcode_to_exe(reinterpret_cast<const char*>(shellcode.data()), shellcode_size, is_64);
    if (exe_data.empty()) {
        std::cerr << "Failed to create executable\n";
        return 1;
    }

    std::cout << "Executable data created successfully. Size: " << exe_data.size() << " bytes\n";

    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        std::cerr << "Error writing to the output file: " << output_path << "\n";
        return 1;
    }

    output_file.write(reinterpret_cast<const char*>(exe_data.data()), exe_data.size());
    output_file.close();

    std::cout << "Executable created successfully: " << output_path << "\n";
    return 0;
}
