## Usage

1. Compile the code using a C++ compiler compatible with Windows.
   
   ```sh
   g++ main.cpp -o main.exe
   ```
2. Run the tool with the name of the target process as a command-line argument:
   ```
   main.exe TargetProcessName.exe
   ```
   Replace TargetProcessName.exe with the name of the process into which you want to inject shellcode.

## Code Explanation
- The tool uses the Windows API to open a target process with OpenProcess.
- It allocates virtual memory within the target process using VirtualAllocEx.
- Shellcode is written to the allocated memory with WriteProcessMemory.
- A remote thread is created using CreateRemoteThread to execute the injected shellcode.

## Disclaimer
The authors and contributors of this code are not responsible for any misuse or unlawful activities related to this tool. Use it responsibly and with proper authorization.

## License
This code is provided under an MIT License. See the [LICENSE](./LICENSE) file for details.