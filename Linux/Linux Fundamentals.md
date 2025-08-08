![linux fundamentls](../attachments/Pasted%20image%2020250807220933.png)

- Everything is a file
- configuration data stored in a text file `/etc/...`

#### components 
- `Bootloader` A piece of code that runs to guide the booting process to start the operating system.
- `OS Kernal` The kernel is the main component of an operating system. It manages the resources for system's I/O devices at the hardware level.
- `Daemons` Background services are called "daemons" in Linux. Their purpose is to ensure that key functions such as scheduling, printing, and multimedia are working correctly. These small programs load after we booted or log into the computer.
- `OS Shell` The operating system shell or the command language interpreter (also known as the command line) is the interface between the OS and the user.
- `Graphics server` This provides a graphical sub-system (server) called "X" or "X-server" that allows graphical programs to run locally or remotely on the X-windowing system. a program that manages everything related to displaying graphics (windows, icons, text, etc.) on your computer screen.
- `Window Manager` Also known as a graphical user interface (GUI). There are many options, including GNOME, KDE, MATE, Unity, and Cinnamon. A desktop environment usually has several applications, including file and web browsers.
- `Utilities` Applications or utilities are programs that perform particular functions for the user or another program.

#### Linux Architecture 

![linux architecture diagram | 300](../attachments/Pasted%20image%2020250807221714.png)


#### Linux file system

| 📁 **Path** | 📝 **What It Is (Beginner Description)** | 🔧 **What It's Used For**                                      |
| ----------- | ---------------------------------------- | -------------------------------------------------------------- |
| `/`         | 🌳 Root of everything                    | The top-level directory; contains all other folders            |
| `/bin`      | 🔤 Basic tools                           | Commands like `ls`, `cp`, `mv` – needed to start the system    |
| `/boot`     | 🥾 Boot folder                           | Files needed to start (boot) Linux, like the kernel            |
| `/dev`      | 🧱 Devices                               | Special files that represent hardware (like USB, disk, etc.)   |
| `/etc`      | ⚙️ Settings                              | System and app configuration files live here                   |
| `/home`     | 🏠 User homes                            | Where your personal files go (one folder per user)             |
| `/lib`      | 📚 Libraries                             | Shared files (like helpers) used by programs at startup        |
| `/media`    | 💽 Auto-mount devices                    | USB drives, DVDs, SD cards appear here when plugged in         |
| `/mnt`      | 📦 Manual mount                          | Temporary spot to "attach" drives or filesystems manually      |
| `/opt`      | 🧩 Optional stuff                        | Extra programs not part of the main system (e.g., custom apps) |
| `/root`     | 👑 Root’s home                           | Personal folder for the root (admin) user                      |
| `/sbin`     | 🛠️ System tools                         | Admin tools and commands (e.g., for repair or boot tasks)      |
| `/tmp`      | ❄️ Temporary                             | Place for temporary files – gets cleaned often                 |
| `/usr`      | 🧠 User system resources                 | Apps, docs, and libraries for users (but shared across system) |
| `/var`      | 📈 Variable data                         | Log files, emails, website data – things that keep changing    |

#### Shell
- `Bourne-Again Shell` (`BASH`)
- Besides Bash, there also exist other shells like [Tcsh/Csh](https://en.wikipedia.org/wiki/Tcsh), [Ksh](https://en.wikipedia.org/wiki/KornShell), [Zsh](https://en.wikipedia.org/wiki/Z_shell), [Fish](https://en.wikipedia.org/wiki/Friendly_interactive_shell) shell and others.
