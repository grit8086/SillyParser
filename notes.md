# PE File Format
PE stands for Portable Executable, a file format for executables used in Windows OS. It is based on the COFF file format. Dynamic link libraries (.dll), kernel modules (.sys), and control panel applications (.cpl) are also considered PE files.

## What is COFF?
COFF is a standardized binary file format used to store compiled code and data before (or after) it gets turned into a final executable program. Think of it as a structured container that holds the output of a compiler, ready to be linked or loaded.

## Why Not Just Compile to .EXE Directly?
When you run `gcc program.c -o program.exe`, the compiler produces the `.o` internally and immediately links it, you just can't see it. The problem is if you have a multi-file project: `program1.c`, `program2.c`, `program3.c`, etc. Every single time you edit a line in `program2.c`, you have to recompile everything, even though you didn't touch the other files. This can take minutes to hours.

This is where compiling to COFF first comes in. If you changed `program2.c`, you can just recompile it to `program2.o` and re-link. It's only 2 steps instead of recompiling everything, because internally `.c` files are turned into `.o` files first.

Continuing on the PE file format: it is a data structure that holds information required for the OS loader to load that executable into memory and execute it.

```plaintext
╔══════════════════════════════════════════════╗
║                  DOS HEADER                  ║ 
╠══════════════════════════════════════════════╣
║                  DOS STUB                    ║
║      (This program cannot be run in DOS)     ║
╠══════════════════════════════════════════════╣
║                 NT HEADERS                   ║
║   ┌──────────────────────────────────────┐   ║
║   │        PE Signature (PE\0\0)         │   ║
║   ├──────────────────────────────────────┤   ║
║   │            File Header               │   ║
║   ├──────────────────────────────────────┤   ║
║   │          Optional Header             │   ║
║   └──────────────────────────────────────┘   ║
╠══════════════════════════════════════════════╣
║                SECTION TABLE                 ║
║         [ .text ][ .data ][ .bss ]...        ║
╠══════════════════════════════════════════════╣
║             SECTION 1 (.text)                ║
║         // machine code lives here           ║
╠══════════════════════════════════════════════╣
║             SECTION 2 (.data)                ║
║      // initialized global variables         ║
╠══════════════════════════════════════════════╣
║              SECTION 3 (.bss)                ║
║       // uninitialized variables             ║
╠══════════════════════════════════════════════╣
║             SECTION 4 (.rdata)               ║
║        // read-only data, strings            ║
╠══════════════════════════════════════════════╣
║                     ...                      ║
╠══════════════════════════════════════════════╣
║              SECTION N (...)                 ║
║           // additional sections             ║
╚══════════════════════════════════════════════╝
```

**DOS Header** - Every PE file starts with a 64-byte structure called the DOS Header, which makes the PE file an MS-DOS executable. It contains the magic number `MZ` (0x5A4D) which marks a valid DOS executable, and crucially, the `e_lfanew` field at offset 0x3C, which points to the start of the NT Headers. This is what parsers use to locate the rest of the PE structure.

**DOS Stub** - A small MS-DOS 2.0 compatible executable that just prints an error message when the program is run in DOS mode. Dead code that nobody needs anymore.

**NT Headers** - Made up of three parts:
- **PE Signature** - A 4-byte signature (`PE\0\0`) that identifies the file as a PE file.
- **File Header** - The standard COFF file header. Contains basic information about the PE file such as target machine architecture, number of sections, and characteristics.
- **Optional Header** - The most important header in the NT Headers. It provides critical information to the OS loader, including the `ImageBase`, `EntryPoint`, and the `DataDirectories` array (which points to structures like the Import and Export tables). Its name is "Optional" because object files don't have it, but it is required for image files like `.exe` and `.dll`.

### Wowowoah, what is an image file?
In the context of PE files, an image file refers to a file that is meant to be loaded directly into memory and executed like `.exe` and `.dll` files.

**Section Table** - An array of section headers, one for each section in the PE file. To parse a specific section's metadata, you iterate over this table.

**Sections** - Where the actual contents of the file are stored. Each section has its own purpose:
- `.text` - compiled machine code
- `.data` - initialized global variables
- `.bss` - uninitialized variables. Takes up no space on disk; the OS loader simply zeroes out this region in memory at runtime.
- `.rdata` - read-only data such as string literals and constants
- `.idata` - import directory; describes which DLLs the executable depends on and which functions it imports from them. One of the most practically important sections for understanding how DLL loading works.

# DOS Header, DOS Stub, and Rich header
The DOS header is a 64-byte long structure that exists at the start of the PE file. It's ntot really imporatnt but its there for backward compatibility reasons of MS-DOS. It makes the executable an MS-DOS so when its loaded on MS-DOS the DOS stub gets executed instead of the actal program.

## Structure
```c
// The DOS header is a legacy structure from the MS-DOS era.
// Every PE file (.exe, .dll, etc.) still starts with this header for backwards compatibility.
// Most fields here were relevant for MS-DOS executables and are essentially dead weight in modern PE files.
// The only two fields you actually care about as a PE parser are e_magic and e_lfanew.

typedef struct _IMAGE_DOS_HEADER {
    WORD   e_magic;                     // Must be 0x5A4D ("MZ"). This is how you confirm the file is a valid DOS/PE executable.
    WORD   e_cblp;                     
    WORD   e_cp;                       
    WORD   e_crlc;                      
    WORD   e_cparhdr;                   
    WORD   e_minalloc;                  
    WORD   e_maxalloc;                  
    WORD   e_ss;                        
    WORD   e_sp;                        
    WORD   e_csum;                     
    WORD   e_ip;                        
    WORD   e_cs;                        
    WORD   e_lfarlc;                    
    WORD   e_ovno;                     
    WORD   e_res[4];                    
    WORD   e_oemid;                     
    WORD   e_oeminfo;                   
    WORD   e_res2[10];                  
    LONG   e_lfanew;                    // THE important field. A file offset (in bytes) pointing to the NT Headers (IMAGE_NT_HEADERS).
                                        // The OS loader jumps straight here to find the real PE structure.
                                        // This is also the first thing any PE parser reads after validating e_magic.
} IMAGE_DOS_HEADER,

// IMAGE_DOS_HEADER is the struct type, used when you have a direct instance, e.g:
// IMAGE_DOS_HEADER dosHeader;

// *PIMAGE_DOS_HEADER is a pointer typedef to the same struct, used when you want to point to one, e.g:
// PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBase;
// This is the common Windows convention, P prefix = pointer. Saves you from writing IMAGE_DOS_HEADER* everywhere.

*PIMAGE_DOS_HEADER;
```

I added comments only on the two important members that we need.
- **e_magic**: first member of the DOS header, it's a WORD and occupies 2 bytes. It serves as a signature that validates the file as an MS-DOS executable. Its value is always `MZ` (0x5A4D).
- **e_lfanew**: last member of the DOS header struct, located at offset `0x3C`, and it holds an offset to the start of the NT headers. This is important because it tells the PE loader where to find the actual PE structure.


## Rich Header
A chunk of data sitting between the DOS Stub and the NT Headers. It's not an official part of the PE format, so you can zero it out completely and the executable still runs fine.

It's only present in executables built with Microsoft Visual Studio, and it stores metadata about the build tools used, things like the tool type, version, and how many times it was used during compilation.

### Structure
The data is XOR-encrypted. To read it, you XOR everything with the 32-bit checksum that follows the `Rich` signature at the end, which doubles as the XOR key.

Once decrypted, the layout is:

```plaintext
[ DanS ][ padding ][ entry ][ entry ][ entry ]...[ Rich ][ XOR key ]
```

- `DanS` and `Rich` are just magic signatures that mark the start and end of the header
- Each entry is a pair of DWORDs: one holding the tool type and build number, the other holding how many times that tool was used

## Why should you care?
You probably won't need to parse this yourself. What matters is knowing it exists and what it's used for forensically.

The Rich Header is a fingerprint of the build environment. Malware analysts use it to attribute samples to threat actors, since two executables built on the same machine with the same toolset will have matching Rich Headers.

This is exactly what happened with **Olympic Destroyer**, a malware used to disrupt the 2018 Winter Olympics. The authors copied the Rich Header from a known Lazarus Group sample into their own malware to fake attribution and throw analysts off.

# NT Headers
Before  we talk about NT headers, let's talk about Relative Virtual Address. 

## Relative Virtual ADddress (RVA)
RVA's the exact offset n memory where a specific section of the image begins once the program is lodded (Image base) 
PE files rely heavily on the use of RVAs.

Here's the formula for getting the RVA and Virtual Adddress:
```plaintext
RVA = Virtual Address - Image Base Address
VA  = Image Base Address + RVA
```

## NT Headers (IMAGE_NT_HEADERS)

