Here's a clean and summarized breakdown of your notes on **File System Management** in Linux, with section-wise clarity for revision:

---

## **1. File System Types**

- **ext2**: No journaling, older, simple, suitable for USBs.
    
- **ext3**: Journaling added; more reliable than ext2.
    
- **ext4**: Default in modern Linux; better performance, large file support.
    
- **Btrfs**: Advanced (snapshots, checksums, subvolumes), good for complex setups.
    
- **XFS**: High performance, handles large files well, ideal for high I/O workloads.
    
- **NTFS**: Windows default, use in dual-boot systems or cross-platform drives.
    

---

## **2. Linux File System Structure**

- **Unix-based hierarchical structure** with root `/` at the top.
    
- **Inodes**: Metadata holders (not file names or content), track permissions, ownership, timestamps, data block pointers.
    
- **Inode Table**: Collection/database of all inodes.
    
- **Analogy**: Inode = library catalog card; File = actual book.
    

---

## **3. File Types in Linux**

- **Regular Files**: Text or binary, most common.
    
- **Directories**: Containers for files; structure and organize data.
    
- **Symbolic Links (symlinks)**: Shortcuts to other files/dirs.
    

---

## **4. File Permissions**

- Users categorized into **owner**, **group**, and **others**.
    
- Permissions: **read (r)**, **write (w)**, **execute (x)**.
    
- Each category has independent permission control.
    

---

## **5. Disk & Partition Management**

- Tools: `fdisk`, `gpart`, `GParted`.
    
- **Partitioning**: Divide disk into logical sections, format with file systems (e.g., ext4, NTFS, FAT32).
    
- **Example**: `sudo fdisk -l` lists disks and partitions:
    
    ```bash
    /dev/vda1 – Linux partition (75.8G)
    /dev/vda2 – Swap (4.2G)
    ```
    

---

## **6. Mounting & Unmounting**

- **Mounting**: Attach a device/partition to a directory (mount point) to access contents.
    
    ```bash
    sudo mount /dev/sdb1 /mnt/usb
    ```
    
- **Unmounting**:
    
    ```bash
    sudo umount /mnt/usb
    ```
    

---

## **7. Persistent Mounts at Boot – `/etc/fstab`**

- Stores permanent mount configurations.
    
- Uses **UUID** for device identification.
    
    ```fstab
    UUID=xxxx /              btrfs   defaults,...
    UUID=xxxx /home          btrfs   defaults,...
    UUID=xxxx swap           swap    defaults
    ```
    

---

## **8. Check Mounted File Systems**

- Use:
    
    ```bash
    mount
    ```
    
- Example output shows mount point, file system type, options:
    
    ```
    /dev/vda1 on / type btrfs (...)
    ```
    

---

## **9. Example: Listing Files with Inodes**

- Command: `ls -il`
    
    ```
    10678872 -rw-r--r-- 1 user group size date myscript.py
    ```
    

---

Would you like this formatted as a PDF or Markdown file for printing or sharing with your team?