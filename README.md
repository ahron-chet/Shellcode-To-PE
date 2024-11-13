# Shellcode to PE Converter

This project converts raw shellcode into a Portable Executable (PE) format, enabling the execution of shellcode within a structured PE.

## Usage
Run the program with the following syntax:
```bash
ShellcodeToPE.exe -out <output_file> -shellcode <shellcode_file_path> -arch <x86|x64>
```

### Example
To convert a raw shellcode file (`shellcode.bin`) to a 64-bit PE executable named `payload.exe`:
```bash
ShellcodeToPE.exe -out payload.exe -shellcode shellcode.bin -arch x64
```
