# Vulpin
**Vul** is a tiny, single character command scripting language that runs on top of Python :)🦊 !  
It was designed to let you write the smallest possible programs while still having full programming power! ;)

# 📦 Installition


* Download Vulpin from **github** or using the gitclone and some of the stuff...

* Download **Python 3**.

* Then **Sync** Vulpin in *system variables*. **Sync it with folder of ```Bin```**

<br>

## 🌠 Quick Start
1. **Create a `.vul` file**. Like `hello.vul`:
   ```vul
   G "Hello from Vul!"
   ```
2. **Run it**:
   ```bash
   python vul.py hello.vul
   ```

If you run `python vul.py` without a filename, it will try to execute `app.vul` in the current directory!
> [!TIP]
> You can remove spaces in your app! dont worry about it! Because if you do that you can build your smalest program like this:
>
> ```G"Hello World"```
---

## 📋🦊 Complete Command Reference

| Char | Name | Syntax | Description |
|------|------|--------|-------------|
| `G` | Print | `G expr` | Print with newline |
| `P` | Print (no nl) | `P expr` | Print without newline |
| `=` | Assign | `var=expr` | Direct assignment (no command letter) |
| `A` | Arithmetic assign | `A"var"op expr` | `var = var op expr` |
| `S` | String replace | `S"var""old""new"` | Replace substring |
| `D` | Delay / Delete | `D seconds` / `D"var"` | Wait or delete a variable |
| `K` | Input | `K"var""prompt""type"` | Read from keyboard (with optional type) |
| `X` | Execute file | `X"file.py"` | Run a Python file in the background |
| `Q` | Quit | `Q` | Exit the program |
| `E` | Error exit | `E"msg"` | Print error and exit |
| `U` | Import | `U"module"` | Import a Python module or `.vul` file |
| `?` | If / Cond jump | `? cond` / `? cond J label` | Conditional execution |
| `:` | Else | `:` | Else clause |
| `;` | Endif | `;` | End if block |
| `@` | While | `@ cond` | Start while loop |
| `&` | Wend / End for | `&` | End loop |
| `O` | For‑range | `O var start end [step]` | Counted loop |
| `L` | Label | `L name` | Define a jump label |
| `J` | Jump | `J label` | Unconditional jump |
| `F` | Function | `F name(params)` | Define a function |
| `R` | Return | `R expr` | Return from function |
| `~` | End function | `~` | End function body |
| `T` | Try | `T` | Start try block |
| `C` | Catch | `C` / `C"var"` | Catch exception |
| `Y` | End try | `Y` | End try/catch |
| `W` | Switch | `W expr` | Start switch block |
| `V` | Case | `V value` | Case in switch |
| `N` | Default | `N` | Default case |
| `Z` | End switch | `Z` | End switch block |
| `!` | Python exec | `! code` | Execute raw Python (multi‑line possible) |
| `#` | Comment | `# text` | Inline comment |

---

## ✨🦊 Basic Syntax

### 🖨️🦊 Output

```vul
G"Hello"           # Prints with newline
P"Loading..."      # Prints without newline
G 5 + 3            # Prints 8
G $name            # Prints value of variable name
```

### 📥🦊 Input

```vul
K"user""Your name: "
G"Hi, " + $user

# Typed input (invalid → default value)
K"age""Age: ""I"        # Integer (default 0)
K"price""Price: ""F"    # Float (default 0.0)
K"letter""Guess: ""L"   # Single letter (default "")
```

**Type characters for `K`:**
| Char | Type | Default if invalid |
|------|------|--------------------|
| `I` | Integer | `0` |
| `F` | Float | `0.0` |
| `N` | Number (int/float) | `0` |
| `L` | Single letter | `""` |
| `W` | Word (letters only) | `""` |
| `E` | Lowercase only | `""` |
| `U` | Uppercase only | `""` |
| `A` | Letters + spaces | `""` |
| `P` | Alphanumeric + spaces | `""` |

### 📦🦊 Variables

```vul
x=10               # Direct assignment
name="Vul"

A"x"+5             # x = x + 5
S"name""Vul""VUL"  # Replace in string
D"y"               # Delete variable
```

**String shortcuts (on any string variable):**
| Shortcut | Method | Example (`$msg.S`) |
|----------|--------|-------------------|
| `.U` | `upper()` | `"hello".U` → `"HELLO"` |
| `.L` | `lower()` | `"HELLO".L` → `"hello"` |
| `.S` | `strip()` | `" hi ".S` → `"hi"` |
| `.T` | `title()` | `"hi there".T` → `"Hi There"` |
| `.C` | `capitalize()` | `"hello".C` → `"Hello"` |

### ⏱️🦊 Delay

```vul
D1          # wait 1 second
D0.5        # wait 0.5 seconds
D $delay    # wait the value of variable
```

### 📚🦊🎁📦 Imports

```vul
U"os"
G $os.getcwd()
$os.system("echo Hello")

U"math"
G $math.sqrt(16)

U"mylib.vul"    # execute another Vul file
```

---

## 🪻🎛️🦊 Control Flow

### `?` / `:` / `;` – If / Else

```vul
score=85
? $score >= 90
    G"A"
:
? $score >= 80
    G"B"
:
    G"C"
;
;
```

### `?` ... `J` – Conditional Jump🦊🦘

```vul
x=5
? $x > 3 J skip
G"Not printed"
L skip
G"Printed"
```

### `@` / `&` – While Loop ➰🦊

```vul
i=0
@ $i < 5
    G $i
    i=$i+1
&
```

### `@ 1` – Infinite Loop ➿🦊

```vul
@ 1
    G"Running forever..."
&
```

### `O` / `&` – For‑Range Loop 🏌️🦊

```vul
O i 0 5            # 0,1,2,3,4
    G $i
&

O x 10 0 -2        # 10,8,6,4,2
    G $x
&
```

### `W` / `V` / `N` / `Z` – Switch / Case🛟🦊

```vul
fruit="apple"
W $fruit
V"banana"   G"yellow"
V"apple"    G"red or green"
N           G"unknown"
Z
```

### `L` / `J` – Labels & Jumps🦊

```vul
J end
G"Skipped"
L end
G"Done"
```

---

## 🔧 Functions

```vul
F add(a, b)
    R $a + $b
~

G $add(3, 4)       # 7

F greet(name)
    G"Hello " + $name
~

$greet("World")
```

---

## 🥷 Error Handling

```vul
T
    x=10
    y=0
    G $x/$y        # division by zero!
C"err"
    G"Error: " + $err
Y
G"Continues..."
```

Output:
```
Error: division by zero
Continues...
```

---

## 🐍🦊 Inline Python (`!`)

### Single line

```vul
!print("Hello from Python")
!x = 42
G $x
```

### Multi‑line (every line starts with `!`)

```vul
!class Dog:
!    def __init__(self, name):
!        self.name = name
!    def speak(self):
!        return "Woof!"

!d = Dog("Buddy")
G $d.name
G $d.speak()
```

---

## 🧪 Complete Examples

### Hello World

```vul
G"Hello World"
```

### Calculator

```vul
K"a""First: ""N"
K"op""Op (+,-,*,/): ""W"
K"b""Second: ""N"
? $op="+" G $a+$b
:? $op="-" G $a-$b
:? $op="*" G $a*$b
:? $op="/" G $a/$b
;
;
;
;
```

### Guessing Game (For practice)

```vul
U"random"
secret=$random.randint(1,10)
tries=0
L guess
K"num""Guess (1-10): ""I"
tries=$tries+1
? $num=$secret
    G"Correct! Tries: "+$tries
    Q
:? $num<$secret G"Higher"
: G"Lower"
;
;
J guess
```

### Factorial

```vul
F factorial(n)
    ? $n<=1
        R 1
    ;
    R $n*$factorial($n-1)
~

G $factorial(5)   # 120
```

---

## Command for check version 🦊

To check the version of Vul you are running:

```bash
vulpin version
```

Output:
```
Vul 0.1
```

# Build your app! [BETA] 🦊👷🏻‍♂️🏗️

* If you want to build your app, first you should install pyinstaller:

```
pip install pyinstaller
```

then all things are right!

### you can build your apps easily like this:

* for build your app as ```default```:
```
vulbuild
```
* for build for ```linux```, ```macos```,```windows```:
```
vulbuild --os all --cross
```
* for build a ```specific OS``` only:
```
vulbuild --os linux --cross
```
```
vulbuild --os windows --cross
```
* for ```package``` your project:
```
vulbuild --os all --cross --package zip tar.gz appimage dmg
```

---
# TroubleShooting💫

Let's fix your problems!

- Python Type Hint Syntax Error:
  this is known error in new Vulpin version like you can see it at most in version ```0.5``` but thats easy to fix!
  - on ***vulpin 0.5*** this error might be in line of ```682``` or line of ```77``` or etc...!
    take a look at here to see how to fix: https://github.com/orgs/community/discussions/199748
---
## 📝 Some of the *notes* that I gonna say...

- **Spaces** are optional after commands. `G"Hi"` and `G "Hi"` both work.
- **All commands are case‑sensitive** – only uppercase for the command letters <mark>(except `!`, `=`, `#`</mark>).
- **The dot operator** (like `$os.name`) works correctly in the latest release. If you encounter issues, use the `--debug` flag to see detailed parser output.

---

## 📄 License
MIT LIECENCE.
CHECK OUT LIECENCE. ELSE I *** U :X
---

**Happy coding with Vul/in! /in yup! All things are built /in with vulp-in :) haha**
