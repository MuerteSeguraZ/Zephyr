# 🌬️ Zephyr Shell

**Zephyr** is a powerful and feature-rich command-line shell for Windows systems designed with versatility, security, and extensibility in mind. With advanced HTTP capabilities, deep system inspection tools, robust file and user management, and networking diagnostics — Zephyr is your all-in-one terminal toolbox.

---

## ✨ Key Features

### 🌐 HTTP Tools
Send and analyze various HTTP requests directly from your shell:
- `http get <url>` — Send a GET request
- `http post <url> <headers|body>` — Send a POST request
- `http put <url> <headers|body>` — Send a PUT request
- `http patch [-H "Header"] [-d "body"] <url>` — Send a PATCH request
- `http delete [-H "Header"] <url>` — Send a DELETE request
- `http head [-H "Header"] <url>` — Send a HEAD request
- `http options [-H "Header"] <url>` — Send an OPTIONS request
- `http trace [-H "Header"] <url>` — Send a TRACE request
- `http link [-H "Header"] <url>` — Send a LINK request
- `http unlink [-H "Header"] <url>` — Send an UNLINK request
- `http propfind [-H "Header"] <url>` — Send a PROPFIND request
- `http connect <proxyHost:port> <targetHost:port> [-H "Header"]` — Proxy tunnel
- `http download <url> <output filename>` — Download a file
- `http pu
- `http help` — HTTP usage reference

---

### 👤 User & Session Management
Inspect and manage user accounts, groups, and active sessions:
- `listusers`, `listlocalusers`, `listadmins`, `listprofiles`
- `listgroups`, `listlocalgroups`, `listgroupmembers [groupname]`
- `listloggedin`, `listremotesessions [-all|-active|-user <name>]`
- `listuserdetails [username]`, `listnetworkusers`
- `listdomains`, `listprocessusers`, `listprivileges`

---

### 🔍 System Inspection
Get detailed insights into your OS, files, processes, memory, and more:
- `inspect file <path>` — File size, timestamps, hashes
- `inspect proc <pid>` — Process info
- `inspect user <username>` — User account details
- `inspect mem`, `inspect net`, `inspect env`, `inspect win`
- `inspect boot` — Boot time, uptime, shutdown reason

---

### 📁 File & Directory Commands
Efficiently manage files, directories, and navigation:
- `list`, `tree`, `look`, `hop`, `whereami`
- `send <src> <dst>`, `shift <src> <dst>` — Copy/Move
- `zap`, `fzap` — Delete and secure delete
- `read`, `peek`, `head`, `tail`, `wc` — Read files
- `write <file> <text>` — Append to file
- `mkplace <dir>`, `mirror <src> <dst>`, `rename`
- `touch`, `find`, `radar`, `stat`, `smlink [-s/-h] <target> <link>`

---

### 🛠️ System Utilities
Explore and control system components:
- `sysinfo`, `version`, `echoe`, `ctitle`
- `cpuinfo`, `gpuinfo`, `raminfo`, `biosinfo`
- `userinfo`, `whoami [-ext]`, `uptime`
- `battery`, `diskinfo`, `du`, `drives`, `smart`
- `procmon`, `killtree <pid>`, `endproc <name>`
- `sconfig <start|stop> <service>`, `mconfig <device> <enable|disable>`
- `checkadmin`, `dnsflush`, `firewall`, `env`, `refreshenv`, `date`

---

### 🌐 Networking Tools
Network diagnostics and monitoring built-in:
- `linkup`, `ntwkadp`, `netstat`
- `pingtest <host>`, `scan <host>`
- `get <url>`, `post`, `header`

---

### 🧪 Miscellaneous
- `run <program>` — Execute an external program
- `bye`, `exit`, `clear` — Exit or refresh shell
- `cutemessage` — 💖 A special hidden feature for someone special
- `help`, `?` — View all available commands

---

## 🛡️ Permissions

`Some features (like service control, firewall, or privilege enumeration) may require Administrator rights. Use checkadmin to verify current elevation status.`

## 🧠 Why Zephyr?
`Zephyr is not just a shell — it's a diagnostic, automation, and inspection powerhouse. Whether you're a sysadmin, power user, or just need precise control over your system, Zephyr has your back.`

# Credits
`Created with care by Muerte. More updates to come.`
`To see proof it works, you can check workingproof/ for some examples of commands.`



## 📦 Build & Run

`To get started with Zephyr, you need to have:`

### The MinGW C++ Compiler.

`After you install that, just run "buildandrun" from the directory Zephyr is in. Make sure to have all the files installed, or just the EXE, it doesn't really matter.`
