![](../attachments/Pasted%20image%2020250906094048.png)

## Assembly Language

Assembly language comes in, as a low-level language that can write direct instructions the processors can understand.

This is why some refer to Assembly language as symbolic machine code. For example, the Assembly code '`add rax, 1`' is much more intuitive and easier to remember than its equivalent machine shellcode '`4883C001`', and easier to remember than the equivalent binary machine code '`01001000 10000011 11000000 00000001`'.

Machine code is often represented as `Shellcode`, a hex representation of machine code bytes. Shellcode can be translated back to its Assembly counterpart and can also be loaded directly into memory as binary instructions to be executed.

![](../attachments/Pasted%20image%2020250906095602.png)

- python
- c
- nasm
- shellcode
- binary

---
---
## Computer Architecture

Today, most modern computers are built on what is known as the [Von Neumann Architecture](https://en.wikipedia.org/wiki/Von_Neumann_architecture), which was developed back in 1945 by `Von Neumann` to enable the creation of "General-Purpose Computers" as `Alan Turing` described them at the time

![](../attachments/Pasted%20image%2020250906101025.png)

### memory
- memory is where the `temporary` data and instructions of currently running programs are located.
- primary memory

two main memory type 
- cache
- random access memory (RAM)

### cache
- memory is usually located within the CPU itself and hence is extremely fast compared to RAM, as it runs at the same clock speed as the CPU.

There are usually three levels of cache memory, depending on their closeness to the CPU core

[yt on levels](https://www.youtube.com/watch?v=IA8au8Qr3lo)

| **Level**       | **Description**                                                                                            |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| `Level 1 Cache` | Usually in kilobytes, the fastest memory available, located in each CPU core. (Only registers are faster.) |
| `Level 2 Cache` | Usually in megabytes, extremely fast (but slower than L1), shared between all CPU cores.                   |
| `Level 3 Cache` | Usually in megabytes (larger than L2), faster than RAM but slower than L1/L2. (Not all CPUs use L3.)       |
### RAM

For example, retrieving an instruction from the registers takes only one clock cycle, and retrieving it from the L1 cache takes a few cycles, while retrieving it from RAM takes around 200 cycles. When this is done billions of times a second, it makes a massive difference in the overall execution speed.

- In assembly, if you can keep data in registers (or at least caches), programs run way faster. Accessing RAM too often slows things down.

Think of RAM like a **partitioned bookshelf**. When a program is loaded, the OS gives it its own **virtual memory space** divided into segments:

|Segment|Purpose|Notes|
|---|---|---|
|**Text**|Contains machine code instructions (read-only)|Where assembly instructions live|
|**Data**|Stores initialized global/static variables|E.g., `int x = 5;`|
|**.bss**|Stores uninitialized globals/statics|E.g., `int y;`|
|**Heap**|Dynamically allocated memory (`malloc`, `new`)|Grows upward (higher addresses)|
|**Stack**|Stores local variables, return addresses|LIFO (push/pop), grows downward|
Each program gets its **own isolated view of memory** (Virtual Memory), even though physically RAM is shared.

the RAM is split into four main `segments`:
![](../attachments/Pasted%20image%2020250906102842.png)

- **Stack**:
    
    - Grows downward (towards lower addresses).
        
    - Fast (just update stack pointer `ESP`/`RSP`).
        
    - Used for: local variables, function calls, return addresses.
        
    - Size is limited — stack overflow happens if you push too much.
        
- **Heap**:
    
    - Grows upward.
        
    - Used for dynamic memory (`malloc`, `free`).
        
    - More flexible but slower — needs OS/kernel to manage.
        

👉 In assembly, you directly work with **stack instructions** (`push`, `pop`, `call`, `ret`) and **heap calls** (via system calls).

### I/O storage 
- **IO devices** = keyboard, screen, disk, network card, USB, etc.
- **Bus interfaces** = highways that move **data (1s and 0s)** and **addresses** between CPU ↔ memory ↔ IO.
    - Width of bus (8-bit, 32-bit, 64-bit, 128-bit) = how much data can move per clock tick.

- cpu never execute directly from disk 
- os loads the program from disk --> into RAM --> CPU executes form RAM

### Speed hierarchy 

|Component|Speed|Size|
|---|---|---|
|**Registers**|Fastest|Bytes|
|**L1 Cache**|~1–5 cycles|KB|
|**L2 Cache**|~10 cycles|MB|
|**L3 Cache**|~30–40 cycles|MB|
|**RAM**|~200 cycles|GB–TB|
|**Storage (HDD/SSD)**|ms-level (thousands of cycles)|TB+|
Closer to CPU = faster, smaller. Farther = slower, bigger.

---
---

## CPU Architecture

**CU** control unit : moves/ controls data tells other parts what to do 
**ALU** arithmetic logic unit : performs math and logic 
The CPU follows an **Instruction Set Architecture (ISA)** — rules for what instructions it understands.
- **RISC** (Reduced Instruction Set Computer): simple instructions, each fast.
- **CISC** (Complex Instruction Set Computer): complex instructions, fewer needed, but each heavier.
	- Intel/AMD CPU -> CISC (x86)
	- ARM (used in mobile, IOT) -> RISC
### clock speed and cycles
- CPU runs at a **clock speed** (e.g., 3.0 GHz = 3 billion ticks per second).
- Each tick = a **clock cycle**, the smallest unit of work.

![](../attachments/Pasted%20image%2020250907123151.png)

### Instruction cycle

every instruction `add rax, 1` goes through this four steps

|Step|Description|Who does it|
|---|---|---|
|**Fetch**|Get instruction from memory (Text segment)|CU|
|**Decode**|Understand what instruction means|CU|
|**Execute**|Perform operation (math/logic)|ALU|
|**Store**|Save result (back to register/memory)|CU|
Example: `add rax, 1`
1. **Fetch** → instruction bytes `48 83 C0 01` pulled from RAM (Text).
2. **Decode** → CPU understands it’s an “add”.
3. **Execute** → ALU adds `1` to value in `rax`.
4. **Store** → result put back into `rax`.

![](../attachments/Pasted%20image%2020250907123436.png)

### sequential vs parallel execution

- older CPUs: executed instruction one after another
- modern CPUs: can run multiple instruction cycles at the same time

### Instruction set architecture (ISA)
- ISA is the language that is understands by CPU
	- example : Intel/AMD use **x86 (32-bit) / x86_64 (64-bit)**.
	- ARM (phones, IoT devices) uses **ARM ISA**.
- each ISA is maps to machine code (1,0) -> to instruction
The same machine code **means different things** on different ISAs.
- `48 83 C0 01` = `add rax, 1` (x86_64).
- But on ARM, those same bytes = something totally different.

This module (and malware analysis in general) = focus on **x86_64 with Intel syntax**.
- **Intel syntax** and **AT&T syntax** are just two _different ways of writing the same instruction for humans_.
- Once assembled, both produce the **same machine code (1s and 0s)** → and the CPU executes it the same way.

#### how to check cpu architecture in linux
```shell
lscpu
OR
uname -m
```

“Little Endian” = means multi-byte numbers are stored **least significant byte first** in memory (important for memory forensics).

---
---
## Instruction Set Architectures

ISA = the **rules of the CPU’s language**.  
It defines **what instructions exist and how they work**.

Each ISA consists of 4 main components:

|Component|What it means|Example|
|---|---|---|
|**Instructions**|Actual operations (opcode + operands). Usually 1–3 operands.|`add rax, 1`, `mov rsp, rax`, `push rax`|
|**Registers**|Small storage inside CPU, super fast.|`rax`, `rsp`, `rip`|
|**Memory Addresses**|Where data/instructions are stored. Can point to RAM or registers.|`0x44d0`, `0xffffffffaa8a25ff`, `$rax`|
|**Data Types**|Size/type of data.|`byte` (8-bit), `word` (16-bit), `dword` (32-bit)|

### CISC (complex instruction set computer)

- **Philosophy:** Do more work per instruction.
- **How:** One complex instruction = fetch, decode, execute, store in a single cycle.
- **Example (x86)**  
    `add rax, rbx` → add `rax + rbx` in one instruction.
- **Why it existed:**
    - Memory was expensive → shorter programs were better.
    - CPU handled complexity, not software.
- **Trade-offs:**
    - Each instruction = heavier → more clock cycles, more power.
    - Processor design is **complex**.

### RISC (Reduced instruction set computer)
- **Philosophy:** Break everything into simple, uniform instructions.
- **How:** Each small step has its own instruction.
- **Example (ARM)**  
    To do the same `rax = rax + rbx`:
    1. `ldr r1, [r2]` → load value from memory
    2. `ldr r3, [r4]` → load another value
    3. `add r1, r2, r3` → perform addition
    4. `str r1, [r5]` → store result
- **Why it works now:**
    - Memory/storage is cheap → longer programs aren’t a big issue.
    - Compiler/assembler optimizes the instructions for speed.
- **Trade-offs:**
    - Needs more instructions per program.
    - BUT → each instruction = **fixed length (32/64-bit)** → predictable timing, faster clock, much lower power.

|Area|CISC|RISC|
|---|---|---|
|**Complexity**|Complex instructions|Simple instructions|
|**Instruction length**|Variable (multiples of 8-bit)|Fixed (32/64-bit)|
|**Instructions per program**|Fewer → shorter code|More → longer code|
|**Optimization**|Hardware handles it|Software (compiler/assembler) handles it|
|**Execution time**|Variable (many clock cycles)|Fixed (1 cycle per stage)|
|**Instruction set size**|~1500+|~200|
|**Power use**|High|Low|
|**Examples**|Intel, AMD|ARM, Apple|

![](../attachments/Pasted%20image%2020250907130813.png)

---
---

## Registers, Addresses and Data Types

### Registers
- tiny super fast storage inside the cpu
- **Data registers** (like `rax, rbx, rcx, rdx, rdi, rsi, r8–r10`) → hold values, syscall arguments, and temporary data.
- **Pointer registers** (like `rbp, rsp, rip`) → hold memory addresses that point to important places:
	- `rbp`: base of the stack frame.
	- `rsp`: current top of the stack.
	- `rip`: address of the next instruction to execute.

Malware analysts care about registers because malware often manipulates `rip` (control flow hijack), `rsp`/`rbp` (stack exploits), and `rax` (syscall numbers & return values).

### sub registers

- Each 64-bit register can be broken into smaller pieces:
    - `rax` (64-bit) → `eax` (32-bit) → `ax` (16-bit) → `al` (8-bit low).
- This allows instructions to only touch part of a register.  
    👉 Example: writing to `al` only changes the **lowest byte of `rax`**.

![](../attachments/Pasted%20image%2020250907145324.png)

Sub-registers can be accessed as:

|Size in bits|Size in bytes|Name|Example|
|---|---|---|---|
|`16-bit`|`2 bytes`|the base name|`ax`|
|`8-bit`|`1 bytes`|base name and/or ends with `l`|`al`|
|`32-bit`|`4 bytes`|base name + starts with the `e` prefix|`eax`|
|`64-bit`|`8 bytes`|base name + starts with the `r` prefix|`rax`|

The following are the names of the sub-registers for all of the essential registers in an x86_64 architecture:

| Description                     | 64-bit Register | 32-bit Register | 16-bit Register | 8-bit Register |
| ------------------------------- | --------------- | --------------- | --------------- | -------------- |
| `Data/Arguments Registers`      |                 |                 |                 |                |
| Syscall Number/Return value     | `rax`           | `eax`           | `ax`            | `al`           |
| Callee Saved                    | `rbx`           | `ebx`           | `bx`            | `bl`           |
| 1st arg - Destination operand   | `rdi`           | `edi`           | `di`            | `dil`          |
| 2nd arg - Source operand        | `rsi`           | `esi`           | `si`            | `sil`          |
| 3rd arg                         | `rdx`           | `edx`           | `dx`            | `dl`           |
| 4th arg - Loop counter          | `rcx`           | `ecx`           | `cx`            | `cl`           |
| 5th arg                         | `r8`            | `r8d`           | `r8w`           | `r8b`          |
| 6th arg                         | `r9`            | `r9d`           | `r9w`           | `r9b`          |
| `Pointer Registers`             |                 |                 |                 |                |
| Base Stack Pointer              | `rbp`           | `ebp`           | `bp`            | `bpl`          |
| Current/Top Stack Pointer       | `rsp`           | `esp`           | `sp`            | `spl`          |
| Instruction Pointer 'call only' | `rip`           | `eip`           | `ip`            | `ipl`          |
