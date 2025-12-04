# 🌬️ Zephyr Shell

**Zephyr** is a powerful and feature-rich command-line shell for Windows systems designed with versatility, security, and extensibility in mind. With advanced HTTP capabilities, deep system inspection tools, robust file and user management, and networking diagnostics — Zephyr is your all-in-one terminal toolbox.

![Build](https://img.shields.io/badge/build-passing-brightgreen)

![Platform](https://img.shields.io/badge/platform-Windows-blue)

![Made With C++](https://img.shields.io/badge/made%20with-C%2B%2B-blue)

![License](https://img.shields.io/badge/license-MIT-green)

![Downloads](https://img.shields.io/github/downloads/MuerteSeguraZ/Zephyr/total?color=purple)


---

## ✨ Key Features

### 🌐 HTTP Tools
Send and analyze various HTTP requests directly from your shell:
- `http get http get <URL> [header1|header2|...] [--cookie-jar file]` — Send a GET request
- `http post <url> <headers|body>` — Send a POST request
- `http put <url> <headers|body>` — Send a PUT request
- `http patch [-H "Header"] [-d "body"] <url>` — Send a PATCH request
- `http patchform [-H "Header"] [-d "body"] <url>` — Send a PATCH request with form data
- `http delete [-H "Header"] <url>` — Send a DELETE request
- `http head [-H "Header"] <url>` — Send a HEAD request
- `http options [-H "Header"] <url>` — Send an OPTIONS request
- `http trace [-H "Header"] <url>` — Send a TRACE request
- `http link [-H "Header"] <url>` — Send a LINK request
- `http unlink [-H "Header"] <url>` — Send an UNLINK request
- `http propfind [-H "Header"] <url>` — Send a PROPFIND request
- `http proppatch [-H "Header"] [--depth 0|1|infinity] -d "<xml>" <url>` — Send a PROPPATCH request
- `http bind [-H "Header"] <url> [body]` — Send a BIND request
- `http rebind [-H "Header"] <url> [body]` — Send a REBIND request
- `http unbind [-H "Header"] <url>` — Send an UNBIND request
- `http connect <proxyHost:port> <targetHost:port> [-H "Header"]` — Proxy tunnel
- `http download <url> <output filename>` — Download a file
- `http purge <URL> [header1|header2|...] [|payload]` - Send an PURGE request
- `http report [-H \"Header: value\"] [-D depth] <url> [body]` — Send an HTTP REPORT request
- `http mkcol [-H \"Header: value\"] <URL> [body]` — Send an HTTP MKCOL request
- `http hug [-H \"Header: value\"] <URL> [body]` — Send an HTTP HUG request
- `http upnp`                   — Send a UPnP discovery request.
- `http help` — HTTP usage reference

---

### 👤 User & Session Management
Inspect and manage user accounts, groups, and active sessions:
- `usermgmt listusers`, `usermgmt listlocalusers`, `usermgmt listadmins`, `usermgmt listprofiles`
- `usermgmt listgroups`, `usermgmt listlocalgroups`, `usermgmt listgroupmembers [groupname]`
- `usermgmt listloggedin`, `usermgmt listremotesessions [-all|-active|-user <name>]`
- `usermgmt listuserdetails [username]`, `usermgmt listnetworkusers`
- `usermgmt listdomains`, `usermgmt listprocessusers`, `usermgmt listprivileges`

---

### 🔍 System Inspection
Get detailed insights into your OS, files, processes, memory, and more:
- `inspect file <path>` — File size, timestamps, hashes
- `inspect proc <pid>` — Process info
- `inspect user <username>` — User account details
- `inspect mem`, `inspect net`, `inspect env`, `inspect win`
- `inspect boot` — Boot time, uptime, shutdown reason

---

### 📈 Diagnostics
Powerful diagnostic tools for system integrity and security:
- `diagnostics integrity [--json|--count|--hotfixid=ID|--after=YYYY-MM-DD]` — Check system file integrity
- `diagnostics drivers [--unsigned|--all|--json]` — List loaded drivers
- `diagnostics defender [--json]` — Check Windows Defender status
- `diagnostics tasks [--json|--last-run|--enabled|--disabled]` — List scheduled tasks

### 📁 File & Directory Commands
Efficiently manage files, directories, and navigation:
- `list`, `tree`, `look`, `hop`, `whereami`
- `send <src> <dst>`, `shift <src> <dst>` — Copy/Move
- `zap`, `fzap` — Delete and secure delete
- `fhash <file>` - Calculate and display the hash of a file
- `fmeta <file>` — View file metadata
- `fsize <file>` — Get file size
- `read`, `peek`, `head`, `tail`, `wc` — Read files
- `write <file> <text>` — Append to file
- `mkplace <dir>`, `mirror <src> <dst>`, `rename`
- `touch`, `find`, `radar`, `stat`, `smlink [-s/-h] <target> <link>`

---

### 🛠️ System Utilities
Explore and control system components:
- `sysinfo`, `version`, `echoe`, `ctitle`
- `cpuinfo`, `gpuinfo`, `raminfo`, `biosinfo`, `motherbinfo`, `meminfo`,
- `userinfo`, `whoami [-ext]`, `uptime`
- `battery`, `diskinfo`, `du`, `drives`, `smart`
- `procmon`, `killtree <pid>`, `endproc <name>`
- `sconfig <start|stop> <service>`, `mconfig <device> <enable|disable>`
- `checkadmin`, `dnsflush`, `firewall`, `env`, `refreshenv`, `date`, `shadowcopies`
- `bgjob`, `fgjob`, `startjob <command>`, `stopjob <jobid>`, `jobs`
---

### 🌐 Networking Tools
Network diagnostics and monitoring built-in:
- `linkup`, `ntwkadp`, `netstat`
- `pingtest <host>`, `scan <host>`

---

### 🧪 Miscellaneous
- `run <program>` — Execute an external program
- `bye`, `exit`, `clear` — Exit or refresh shell
- `clipcopy`, `clipclear` - Copy text to clipboard or clear clipboard
- `help`, `?` — View all available commands

---

## 🎩 Scripts Support
`Zephyr supports running various script files directly from the shell, including:`
- `.bat`
- `.exe`
- `.ps1`
- `.py`
- `.js`
- `.cpp`
- `.vbs`
- `It also reads from PATH and PATHEXT.`

## 🛡️ Permissions

`Some features (like service control, firewall, or privilege enumeration) may require Administrator rights. Use checkadmin to verify current elevation status.`

## 🧠 Why Zephyr?
`Zephyr is not just a shell — it's a diagnostic, automation, and inspection powerhouse. Whether you're a sysadmin, power user, or just need precise control over your system, Zephyr has your back.`

# Credits
`Created with care by Muerte. More updates to come.`
`"WE AINT PLAYING NO GAMES HERE 🗣🗣🗣"`

## 📦 Build & Run

`To get started with Zephyr, you need to have:`

### The MinGW C++ Compiler.

`After you install that, just run "buildandrun" from the directory Zephyr is in. Make sure to have all the files installed, or just the EXE, it doesn't really matter.`

`You can also do:`

`git clone https://github.com/MuerteSeguraZ/Zephyr.git`

`cd Zephyr`

`buildandrun.bat`
