
---

## 📜 File Viewing & Editing – Cheat Sheet

|**Command**|**Description**|**Example Usage**|
|---|---|---|
|`cat`|Displays content of a file.|`cat file.txt`|
|`cat >`|Creates a new file and takes input. Ends with `Ctrl + D`.|`cat > new.txt`|
|`cat >>`|Appends text to an existing file.|`cat >> file.txt`|

---

## 📝 `vim` Editor – Detailed Beginner-to-Pro Cheat Sheet

### 🔹 **1. Starting & Exiting Vim**

|Command|Description|
|---|---|
|`vim filename`|Open or create a file in vim|
|`:q`|Quit (only if no changes made)|
|`:q!`|Force quit without saving|
|`:w`|Save file|
|`:wq` or `ZZ`|Save and quit|
|`:x`|Save and quit (same as `:wq`)|

---

### 🔹 **2. Modes in Vim**

|Mode|Action|
|---|---|
|Normal Mode|Default mode – for navigation & commands|
|Insert Mode|For typing text – enter it using `i`, `a`, etc.|
|Visual Mode|For selecting text – enter it using `v`|
|Command Mode|For `:` commands like `:w`, `:q`, etc.|

---

### 🔹 **3. Entering Insert Mode**

|Command|Description|
|---|---|
|`i`|Insert before the cursor|
|`I`|Insert at the beginning of the line|
|`a`|Append after the cursor|
|`A`|Append at the end of the line|
|`o`|Open a new line below|
|`O`|Open a new line above|

---

### 🔹 **4. Navigation in Normal Mode**

|Command|Moves the cursor...|
|---|---|
|`h`|Left|
|`l`|Right|
|`j`|Down|
|`k`|Up|
|`0`|To beginning of line|
|`^`|To first non-blank character|
|`$`|To end of line|
|`gg`|To beginning of file|
|`G`|To end of file|
|`:n`|To line number `n` (e.g. `:5`)|

---

### 🔹 **5. Editing Text**

|Command|Description|
|---|---|
|`x`|Delete character under cursor|
|`dd`|Delete (cut) the current line|
|`yy`|Copy the current line|
|`p`|Paste after the cursor|
|`P`|Paste before the cursor|
|`u`|Undo last change|
|`Ctrl + r`|Redo|
|`cw`|Change word|
|`C`|Change from cursor to end of line|
|`r<char>`|Replace a single character|

---

### 🔹 **6. Visual Mode (Text Selection)**

|Command|Description|
|---|---|
|`v`|Start visual mode (character select)|
|`V`|Start line selection mode|
|`Ctrl + v`|Start block selection mode|
|`y`|Copy selected text|
|`d`|Cut selected text|
|`p`|Paste after cursor|

---

### 🔹 **7. Searching**

|Command|Description|
|---|---|
|`/word`|Search forward for "word"|
|`?word`|Search backward for "word"|
|`n`|Repeat last search forward|
|`N`|Repeat last search backward|

---

### 🔹 **8. Replace**

|Command|Description|
|---|---|
|`:%s/old/new/g`|Replace all `old` with `new` in the file|
|`:s/old/new/g`|Replace all `old` with `new` in the current line|
|`:%s/old/new/gc`|Replace with confirmation|

---

### 🔹 **9. Split Screens**

|Command|Description|
|---|---|
|`:split filename`|Horizontal split|
|`:vsplit filename`|Vertical split|
|`Ctrl + w + w`|Switch between splits|
|`Ctrl + w + q`|Quit current split|

---

### 🔹 **10. Miscellaneous**

|Command|Description|
|---|---|
|`:set number`|Show line numbers|
|`:set nonumber`|Hide line numbers|
|`:help`|Open Vim help|
|`:syntax on`|Enable syntax highlighting|

---

