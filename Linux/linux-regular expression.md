## 🔍 Regular Expressions (Regex)

Regular expressions (regex) allow powerful pattern matching in text. Useful with tools like `grep`, `sed`, `awk`, etc.

---

### **1. Basic Symbols**

|Symbol|Meaning|Example|
|---|---|---|
|`.`|Any single character|`a.c` matches `abc`, `axc`|
|`^`|Start of line|`^root` matches lines starting with `root`|
|`$`|End of line|`bash$` matches lines ending in `bash`|
|`*`|Zero or more of previous char|`lo*` matches `l`, `lo`, `loo`|
|`+`|One or more of previous char|`go+` matches `go`, `goo` (only with `grep -E`)|
|`?`|Zero or one of previous char|`colou?r` matches `color` and `colour`|
|`[]`|Match any one character|`[aeiou]` matches any vowel|
|`[^]`|Negated set|`[^0-9]` matches non-digit|
|`{n}`|Exactly n times|`[0-9]{3}` matches 3 digits|
|`{n,m}`|Between n and m times|`[a-z]{2,4}` matches 2 to 4 lowercase letters|
|`\`|Escape special characters|`\.` matches literal dot|

---

### **2. Grouping ( )**

Groups expressions and captures matches.

```bash
echo "abc123" | grep -E "(abc)[0-9]+"
```

---

### **3. OR Operator (`|`)**

Used to match either pattern.

```bash
echo "apple" | grep -E "apple|orange"
```

---

### **4. AND Operator (Grep workaround)**

Use piped `grep` commands to simulate AND:

```bash
echo "apple banana orange" | grep "apple" | grep "banana"
```

---

### **5. Anchors and Ranges Examples**

```bash
grep "^root" /etc/passwd             # Lines starting with root
grep "bash$" /etc/passwd             # Lines ending in bash
grep -E "[0-9]{3}" file.txt          # Any line with 3-digit number
grep -E "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" file.txt   # Match emails
grep -E "\b(cat|dog)\b" file.txt    # Match whole word cat or dog
```

---

### **6. Practical Use Cases**

#### ✅ Match IP addresses

```bash
grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" file.txt
```

#### ✅ Match date format (YYYY-MM-DD)

```bash
grep -E "[0-9]{4}-[0-9]{2}-[0-9]{2}" file.txt
```

#### ✅ Match lines not containing a word

```bash
grep -v "error" logfile.txt
```

---

### ✅ Tips

- Use `grep -E` for extended regex (ERE)
    
- Always quote regex patterns to avoid shell interpretation
    
- Combine `grep`, `sed`, and `awk` for powerful text processing pipelines
    

Let me know if you want a practice worksheet for these!