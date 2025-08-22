
---

## 1. **more**

Displays file content one page at a time.

**Syntax:** `more [filename]`

**Usage:**

```bash
more longfile.txt
```

**Navigation:**

- `Space`: Next page
    
- `Enter`: Next line
    
- `q`: Quit
    

---

## 2. **less**

Advanced pager than `more`. Allows both forward and backward navigation.

**Syntax:** `less [filename]`

**Usage:**

```bash
less longfile.txt
```

**Navigation:**

- `Space`: Next page
    
- `b`: Back a page
    
- `q`: Quit
    

---

## 3. **head**

Prints the first N lines of a file.

**Syntax:** `head [options] [file]`

**Examples:**

```bash
head file.txt                  # First 10 lines (default)
head -n 20 file.txt            # First 20 lines
```

---

## 4. **tail**

Prints the last N lines of a file.

**Syntax:** `tail [options] [file]`

**Examples:**

```bash
tail file.txt                  # Last 10 lines
tail -n 20 file.txt            # Last 20 lines
tail -f logfile.log            # Live monitor logs
```

---

## 5. **sort**

Sorts lines of text files.

**Syntax:** `sort [options] [file]`

**Examples:**

```bash
sort names.txt                 # Sort alphabetically
sort -r names.txt              # Reverse order
sort -n numbers.txt            # Numerical sort
sort -k 2 data.txt             # Sort by 2nd column
sort -u names.txt              # Unique sorted
```

---

## 6. **grep**

Searches for patterns in files.

**Syntax:** `grep [options] pattern [file]`

**Examples:**

```bash
grep "hello" file.txt
grep -i "hello" file.txt       # Case-insensitive
grep -r "main" /path/to/code   # Recursive
grep -v "error" logs.txt       # Invert match
```

---

## 7. **cut**

Cuts out sections from each line of files.

**Syntax:** `cut [options] [file]`

**Examples:**

```bash
cut -c 1-5 file.txt            # First 5 characters
cut -d "," -f 1 names.csv      # First column (CSV)
cut -d ":" -f 1 /etc/passwd    # Get usernames
```

---

## 8. **tr**

Translates or deletes characters.

**Syntax:** `tr [options] SET1 [SET2]`

**Examples:**

```bash
echo "hello 123" | tr a-z A-Z         # Uppercase
echo "text 123" | tr -d '0-9'         # Delete digits
```

---

## 9. **column**

Formats text into columns.

**Syntax:** `column [options]`

**Examples:**

```bash
cat data.txt | column -t             # Align columns with tabs
column -s "," -t < data.csv          # CSV as table
```

---

## 10. **awk**

Powerful text processing tool.

**Syntax:** `awk 'pattern {action}' file`

**Examples:**

```bash
awk '{print $1}' data.txt           # Print first column
awk -F":" '{print $1, $3}' /etc/passwd
awk '/error/ {print $0}' logfile    # Filter error lines
```

---

## 11. **sed**

Stream editor for filtering and transforming text.

**Syntax:** `sed [options] 'command' file`

**Examples:**

```bash
sed 's/error/ERROR/' file.txt       # Replace first occurrence
sed 's/error/ERROR/g' file.txt      # Replace all
sed -n '2,4p' file.txt              # Print lines 2 to 4
```

---

## 12. **wc**

Counts lines, words, and characters.

**Syntax:** `wc [options] [file]`

**Examples:**

```bash
wc file.txt                         # All counts
wc -l file.txt                      # Line count
wc -w file.txt                      # Word count
wc -c file.txt                      # Byte count
```

---

