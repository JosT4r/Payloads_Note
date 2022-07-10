# 赏金猎人漏洞工具

## 分类

* [子域枚举](#子域枚举)
* [端口扫描](#端口扫描)
* [截图](#截图)
* [扫描](#扫描)
* [内容发现](#内容发现)
* [模糊测试](#模糊测试)
* [命令注入](#命令注入)
* [CORS_配置错误](#CORS_配置错误)
* [CRLF_注射](#CRLF_注射)
* [CSRF_注入](#CSRF_注入)
* [目录遍历](#目录遍历)
* [文件包含](#文件包含)
* [GraphQL_注入](#GraphQL_注入)
* [不安全的反序列化](#不安全的反序列化)
* [不安全的直接对象引用](#不安全的直接对象引用)
* [打开重定向](#打开重定向)
* [条件竞争](#条件竞争)
* [请求走私](#请求走私)
* [服务器端请求伪造](#服务器端请求伪造)
* [SQL_注入](#SQL_注入)
* [XSS_注入](#XSS_注入)
* [XXE_注射液](#XXE_注射液)
* [密码_敏感信息](#密码_敏感信息)
* [Git](#Git)
* [云安全S3桶](#云安全S3桶)
* [内容管理系统](#内容管理系统)
* [JSON_网络令牌](#JSON_网络令牌)
* [子域接管](#子域接管)
* [漏洞扫描器](#漏洞扫描器)
* [未分类](#未分类)


## 子域枚举
```
Sublist3r 2 - 用于渗透测试人员的快速子域枚举工具
Amass - 深入的攻击面映射和资产发现
massdns 1 — 用于批量查找和侦察（子域枚举）的高性能 DNS 存根解析器
Findomain 2 — 最快的跨平台子域枚举器，不要浪费你的时间。
Sudomy — Sudomy 是一个子域枚举工具，用于收集子域并分析执行自动侦察 (recon) 以进行错误搜索/渗透测试的域
chaos-client — 与 Chaos DNS API 通信的客户端。
domained - 多工具子域枚举
bugcrowd-levelup-subdomain-enumeration — 此存储库包含在 Bugcrowd LevelUp 2017 虚拟会议上发表的“深奥的子域枚举技术”演讲中的所有材料
shuffledns — shuffleDNS 是用 go 编写的围绕 massdns 的包装器，它允许您使用主动蛮力枚举有效的子域，以及通过通配符处理和简单的输入输出来解析子域……
censys-subdomain-finder — 使用来自 Censys 的证书透明度日志执行子域枚举。
Turbolist3r 1 — 具有已发现域分析功能的子域枚举工具
censys-enumeration 1 — 使用 Censys 上的 SSL/TLS 证书数据集为给定域提取子域/电子邮件的脚本
tugarecon — 用于渗透测试人员的快速子域枚举工具。
as3nt — 另一个子域枚举工具
Subra 1 — 子域枚举的 Web-UI（子查找器）
Substr3am — 通过监视正在颁发的 SSL 证书对感兴趣的目标进行被动侦察/枚举
domain — 用于 Regon-ng 的 enumall.py 设置脚本
altdns — 生成子域的排列、更改和突变，然后解析它们
brutesubs 1 — 一个自动化框架，用于通过 Docker Compose 使用您自己的词表运行多个开源子域暴力破解工具（并行）
dns-parallel-prober - 他是一个并行化的域名探测器，可以尽可能快地找到给定域的尽可能多的子域。
dnscan 1 — dnscan 是一个基于 python 单词表的 DNS 子域扫描器。
knock — Knockpy 是一个 Python 工具，旨在通过一个词表枚举目标域上的子域。
hakrevdns — 用于执行大量反向 DNS 查找的小型、快速工具。
dnsx — Dnsx 是一个快速且多用途的 DNS 工具包，允许使用用户提供的解析器列表运行您选择的多个 DNS 查询。
subfinder 1 — Subfinder 是一个子域发现工具，可以为网站发现有效的子域。
assetfinder — 查找与给定域相关的域和子域
crtndstry 1 — 另一个子域查找器
VHostScan 1 — 执行反向查找的虚拟主机扫描程序
scilla — 信息收集工具 — DNS / 子域 / 端口 / 目录枚举
```
## 端口扫描
```
masscan — TCP 端口扫描器，异步发送 SYN 数据包，在 5 分钟内扫描整个 Internet。
RustScan 1 — 现代端口扫描器
naabu 1 — 用 go 编写的快速端口扫描器，专注于可靠性和简单性。
nmap — Nmap — 网络映射器。SVN 官方仓库的 Github 镜像。
sandmap - 类固醇上的 Nmap。简单的 CLI，能够运行纯 Nmap 引擎、31 个模块和 459 个扫描配置文件。
ScanCannon — 将 masscan 的速度与 nmap 的可靠性和详细枚举相结合
```
## 截图
```
yeWitness 2 — EyeWitness 旨在截取网站截图，提供一些服务器标头信息，并在可能的情况下识别默认凭据。
aquatone — Aquatone 是一种用于对大量主机上的网站进行可视化检查的工具，便于快速了解基于 HTTP 的攻击面。
screenshoteer - 从命令行制作网站截图和移动仿真。
gowitness — gowitness — 一个使用 Chrome Headless 的 golang 网络截图实用程序
WitnessMe - Web Inventory 工具，使用 Pyppeteer（无头 Chrome/Chromium）截取网页截图，并提供一些额外的花里胡哨，让生活更轻松。
eyeballer - 用于分析渗透测试屏幕截图的卷积神经网络
scrying - 一种用于在一个地方收集 RDP、Web 和 VNC 屏幕截图的工具
Depix — 从像素化屏幕截图中恢复密码
httpscreenshot — HTTPScreenshot 是一种用于抓取大量网站的屏幕截图和 HTML 的工具。
```

## 扫描
```
wappalyzer 3 — 识别网站上的技术。
webanalyze 1 — Wappalyzer 的端口（揭示网站上使用的技术）以自动进行大规模扫描。
python-builtwith — BuiltWith API 客户端
whatweb — 下一代网络扫描仪
retire.js 2 — 检测使用已知漏洞的 JavaScript 库的扫描程序
```
## 内容发现
```

gobuster — 用 Go 编写的目录/文件、DNS 和 VHost 破坏工具
recursebuster — 用于递归查询网络服务器的快速内容发现工具，在渗透测试和网络应用程序评估中很方便
feroxbuster — 一个用 Rust 编写的快速、简单、递归的内容发现工具。
dirsearch — Web 路径扫描器
dirsearch — dirsearch 的 Go 实现。
filebuster — 一个非常快速和灵活的 web fuzzer
dirstalk — dirbuster/dirb 的现代替代品
dirbuster-ng — dirbuster-ng 是 Java dirbuster 工具的 C CLI 实现
gospider — Gospider — 用 Go 编写的快速网络蜘蛛
hakrawler — 简单、快速的网络爬虫，旨在轻松、快速地发现网络应用程序中的端点和资产
LinkFinder 1 — 在 JavaScript 文件中查找端点的 Python 脚本
JS-Scan — 一个 .js 扫描器，内置在 php 中。旨在抓取网址和其他信息
LinksDumper — 从响应中提取（链接/可能的端点）并通过解码/排序过滤它们
GoLinkFinder — 一个快速且最小的 JS 端点提取器
BurpJSLinkFinder — Burp 扩展，用于被动扫描 JS 文件以查找端点链接。
urlgrab — 一个 golang 实用程序，用于通过网站搜索其他链接。
waybackurls — 获取 Wayback Machine 知道的域的所有 URL
gau — 从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 获取已知 URL。
getJS 1 — 快速获取所有 javascript 源/文件的工具
```

## 模糊测试
```
parameth 1 - 此工具可用于暴力发现 GET 和 POST 参数
param-miner——这个扩展识别隐藏的、未链接的参数。它对于查找 Web 缓存中毒漏洞特别有用。
ParamPamPam - 这个工具用于暴力发现 GET 和 POST 参数。
Arjun — HTTP 参数发现套件。
ParamSpider - 从 Web 档案的黑暗角落挖掘参数
wfuzz — Web 应用程序模糊器
ffuf — 用 Go 编写的快速网络模糊器
fuzzdb - 黑盒应用程序故障注入和资源发现的攻击模式和原语字典。
IntruderPayloads — Burpsuite Intruder 有效负载、BurpBounty 有效负载、模糊列表、恶意文件上传和 Web 渗透测试方法和清单的集合。
fuzz.txt 1 — 潜在危险文件
fuzzilli — JavaScript 引擎 Fuzzer
fuzzapi — Fuzzapi 是用于 REST API 渗透测试的工具，使用 API_Fuzzer gem
qsfuzz — qsfuzz（查询字符串模糊）允许您构建自己的规则来模糊查询字符串并轻松识别漏洞。
```
## 命令注入
```
commix 1 — 自动化的一体化操作系统命令注入和利用工具。
```
## CORS_配置错误
```
orsy 1 - CORS 错误配置扫描器
CORStest — 一个简单的 CORS 错误配置扫描器
cors-scanner — 一个多线程扫描器，有助于识别 CORS 缺陷/错误配置
CorsMe - 跨域资源共享错误配置扫描器
```
## CRLF_注射
```
crlfuzz — 一个快速扫描用 Go 编写的 CRLF 漏洞的工具
CRLF-Injection-Scanner — 用于在域列表上测试 CRLF 注入的命令行工具。
Injectus 1 - CRLF 和开放重定向模糊器
CRLFsuite - 一款专为扫描而设计的快速工具CRLF injection
```
## CSRF_注入
```
XSRFProbe 2 - Prime 跨站请求伪造 (CSRF) 审计和利用工具包。
```
## 目录遍历
```
dotdotpwn 1 — DotDotPwn — 目录遍历模糊器
FDsploit 1 - 文件包含和目录遍历模糊、枚举和利用工具。
off-by-slash — Burp 扩展，通过大规模 NGINX 错误配置检测别名遍历。
liffier — 厌倦了在可能的路径遍历中手动添加点-点-斜线？这个简短的片段将增加…/ 在 URL 上。
```
## 文件包含
```
liffy - 本地文件包含利用工具
Burp-LFI-tests — 使用 Burpsuite 对 LFI 进行模糊测试
LFI-Enum — 通过 LFI 执行枚举的脚本
LFISuite — 全自动 LFI Exploiter (+ Reverse Shell) 和扫描仪
LFI-files 1 - 用于 LFI 暴力破解的 Wordlist
```
## GraphQL_注入
```
inql — InQL — GraphQL 安全测试的 Burp 扩展
GraphQLmap — GraphQLmap 是一个脚本引擎，用于与 graphql 端点交互以进行渗透测试。
shapeshifter 1 — GraphQL 安全测试工具
graphql_beautifier — Burp Suite 扩展以帮助使 Graphql 请求更具可读性
liffier ——尽管禁用了自省，但仍获得 GraphQL API 模式
headi 1 — 可定制和自动化的 HTTP 标头注入。
```
## 不安全的反序列化
```
ysoserial — 一种概念验证工具，用于生成利用不安全 Java 对象反序列化的有效负载。
GadgetProbe — 探测使用 Java 序列化对象的端点，以识别远程 Java 类路径上的类、库和库版本。
ysoserial.net — 用于各种 .NET 格式化程序的反序列化有效负载生成器
phpggc — PHPGGC 是一个 PHP unserialize() 有效负载库以及一个从命令行或以编程方式生成它们的工具。

```
## 不安全的直接对象引用
```
Autorize — 由 Barak Tawily 开发的用 Jython 编写的 burp 套件的自动授权强制检测扩展
```
## 打开重定向
```
Oralyzer — 开放式重定向分析器
Injectus 1 - CRLF 和开放重定向模糊器
dom-red — 检查域列表以防止开放重定向漏洞的小脚本
gen.py - 打开 url 重定向有效负载生成器
OpenRedireX — OpenRedirect 问题的 Fuzzer
```
## 条件竞争
```
razzer - 一个专注于种族错误的内核模糊器
racepwn - 竞争条件框架
requests-racer - 小型 Python 库，可以轻松利用请求在 Web 应用程序中利用竞争条件。
turbo-intruder — Turbo Intruder 是一个 Burp Suite 扩展，用于发送大量 HTTP 请求并分析结果。
race-the-web — 测试 Web 应用程序中的竞争条件。包括一个 RESTful API 以集成到持续集成管道中。
```
## 请求走私
```
http-request-smuggling 1 — HTTP 请求走私检测工具
smuggler — Smuggler — 用 Python 3 编写的 HTTP 请求走私/异步测试工具
h2csmuggler — 通过 HTTP/2 明文 (h2c) 进行的 HTTP 请求走私
tiscripts 1 — 这些脚本用于为 CLTE 和 TECL 风格的攻击创建请求走私异步负载。
```
## 服务器端请求伪造
```
SSRFmap — 自动 SSRF 模糊器和开发工具
Gopherus - 该工具生成 gopher 链接，用于利用 SSRF 并在各种服务器中获得 RCE
ground-control — 在我的 Web 服务器上运行的脚本集合。主要用于调试SSRF、blind XSS、XXE漏洞。
SSRFire — 一个自动 SSRF 查找器。只需提供域名和您的服务器即可！
```
## SQL_注入
```
sqlmap 2 — 自动 SQL 注入和数据库接管工具
NoSQLMap — 自动化 NoSQL 数据库枚举和 Web 应用程序开发工具。
SQLiScanner — 使用 Charles 和 sqlmap api 的自动 SQL 注入
SleuthQL — Python3 Burp History 解析工具，用于发现潜在的 SQL 注入点。与 SQLmap 一起使用。
mssqlproxy — mssqlproxy 是一个工具包，旨在通过受感染的 Microsoft SQL Server 通过套接字重用在受限环境中执行横向移动
sqli-hunter — SQLi-Hunter 是一个简单的 HTTP / HTTPS 代理服务器和一个 SQLMAP API 包装器，使挖掘 SQLi 变得容易。
waybackSqliScanner 1 — 从 Wayback 机器收集 url，然后测试每个 GET 参数以进行 sql 注入。
ESC — Evil SQL Client (ESC) 是一个交互式 .NET SQL 控制台客户端，具有增强的 SQL Server 发现、访问和数据泄露功能。
mssqli-duet — MSSQL 的 SQL 注入脚本，它基于 RID 暴力破解从 Active Directory 环境中提取域用户
burp-to-sqlmap — 使用 SQLMap 对 Burp Suite 批量请求执行 SQLInjection 测试
BurpSQLTruncSanner — 针对 SQL 截断漏洞的凌乱 BurpSuite 插件。
andor — 使用 Golang 的盲 SQL 注入工具
Blinder — 一个 python 库，用于自动化基于时间的盲 SQL 注入
sqliv — 大规模 SQL 注入漏洞扫描器
nosqli — NoSql 注入 CLI 工具，用于使用 MongoDB 查找易受攻击的网站。
```
## XSS_注入
```
XSStrike — 最先进的 XSS 扫描器。
xssor2 1 — XSS'OR — 用 JavaScript 破解。
xsscrapy — XSS 蜘蛛 — 检测到 66/66 wavsep XSS
sleepy-puppy — Sleepy Puppy XSS 有效负载管理框架
ezXSS — ezXSS 是渗透测试人员和漏洞赏金猎人测试（盲）跨站点脚本的一种简单方法。
xsshunter — XSS Hunter 服务 — XSSHunter.com的可移植版本
dalfox ——DalFox(Finder Of XSS)/基于golang的参数分析和XSS扫描工具
xsser — 跨站点“脚本编写器”（又名 XSSer）是一个自动框架，用于检测、利用和报告基于 Web 的应用程序中的 XSS 漏洞。
XSpear — 强大的 XSS 扫描和参数分析工具&gem
武器化-XSS-payloads — XSS 有效载荷旨在将 alert(1) 变为 P1
tracy — 一种旨在帮助查找 Web 应用程序的所有接收器和源并以易于理解的方式显示这些结果的工具。
ground-control — 在我的 Web 服务器上运行的脚本集合。主要用于调试SSRF、blind XSS、XXE漏洞。
xssValidator — 这是一个 burp 入侵者扩展程序，旨在自动化和验证 XSS 漏洞。
JSShell — 交互式多用户 Web JS shell
bXSS — bXSS 是一种实用程序，可供错误猎人和组织用来识别盲跨站点脚本。
docem — 在 docx、odt、pptx 等中嵌入 XXE 和 XSS 有效负载的实用工具（类固醇上的 OXML_XEE）
XSS-Radar — XSS Radar 是一种工具，可以检测参数并对其进行模糊处理以发现跨站点脚本漏洞。
BruteXSS — BruteXSS 是一个用 python 编写的工具，用于查找 Web 应用程序中的 XSS 漏洞。
findom-xss — 一个基于 DOM 的快速简单的 XSS 漏洞扫描器。
domdig — 用于单页应用程序的 DOM XSS 扫描器
femida — Burp Suite 的自动盲 xss 搜索
B-XSSRF — 检测和跟踪 Blind XSS、XXE 和 SSRF的工具包
domxssscanner — DOMXSS Scanner 是一个在线工具，用于扫描基于 DOM 的 XSS 漏洞的源代码
xsshunter_client — XSS Hunter 的相关注入代理工具
extended-xss-search — 我的 xssfinder 工具的更好版本 — 在 url 列表中扫描不同类型的 xss。
xssmap — XSSMap 是基于 XSS 的 Python3 开发检测漏洞的工具
XSSCon — XSSCon：简单的 XSS 扫描器工具
BitBlinder — BurpSuite 扩展，用于在提交的每个表单/请求上注入自定义跨站点脚本有效负载，以检测盲 XSS 漏洞
XSSOauthPersistence — 通过 XSS 和 Oauth 维护帐户持久性
shadow-workers ——Shadow Workers 是一个免费的开源 C2 和代理，专为渗透测试人员设计，以帮助利用 XSS 和恶意 Service Workers (SW)
rexsser - 这是一个 burp 插件，它使用正则表达式从响应中提取关键字并测试目标范围内的反射 XSS。
xss-flare — cloudflare 无服务器工作者的 XSS 猎人。
Xss-Sql-Fuzz — burpsuite 插件对GP所有参数（过滤特殊参数）一键自动添加xs sql payload 进行fuzz
vaya-ciego-nen — 检测、管理和利用盲跨站点脚本 (XSS) 漏洞。
dom-based-xss-finder — 查找基于 DOM 的 XSS 漏洞的 Chrome 扩展
XSSTerminal — 使用交互式输入开发您自己的 XSS Payload
xss2png — PNG IDAT 块 XSS 有效负载生成器
XSSwagger — 一个简单的 Swagger-ui 扫描器，可以检测易受各种 XSS 攻击的旧版本
```
## XXE_注射液
```
ground-control — 在我的 Web 服务器上运行的脚本集合。主要用于调试SSRF、blind XSS、XXE漏洞。
dtd-finder — 列出 DTD 并使用这些本地 DTD 生成 XXE 有效负载。
docem — 在 docx、odt、pptx 等中嵌入 XXE 和 XSS 有效负载的实用工具（类固醇上的 OXML_XEE）
xxeserv — 一个小型网络服务器，支持 XXE 有效负载的 FTP
xxexploiter — 帮助利用 XXE 漏洞的工具
B-XSSRF — 检测和跟踪 Blind XSS、XXE 和 SSRF的工具包
XXEinjector — 使用直接和不同的带外方法自动利用 XXE 漏洞的工具。
oxml_xxe — 将 XXE/XML 漏洞嵌入不同文件类型的工具
metahttp — 一个 bash 脚本，通过 XXE 自动扫描目标网络以查找 HTTP 资源
```
## 密码_敏感信息
```
thc-hydra — Hydra 是一个并行登录破解程序，支持多种协议进行攻击。
DefaultCreds-cheat-sheet 1 - 所有默认凭据的一个位置，以帮助蓝/红团队活动查找具有默认密码的设备
changeme — 默认凭据扫描程序。
BruteX — 自动暴力破解目标上运行的所有服务。
patator — Patator 是一个多用途的暴力破解工具，具有模块化设计和灵活的使用方式。
git-secrets — 防止您将机密和凭据提交到 git 存储库中
gitleaks — 使用正则表达式和熵扫描 git repos（或文件）的秘密
truffleHog — 在 git 存储库中搜索高熵字符串和秘密，深入挖掘提交历史
gitGraber — gitGraber：监控 GitHub 以实时搜索和查找不同在线服务的敏感数据
talisman——通过挂钩 Git 提供的 pre-push 钩子，Talisman 验证传出变更集是否存在可疑的东西——例如授权令牌和私钥。
GitGot - 半自动化、反馈驱动的工具，用于快速搜索 GitHub 上的大量公共数据以查找敏感机密。
git-all-secrets 1 — 通过利用多个开源 git 搜索工具来捕获所有 git 机密的工具
github-search — 在 GitHub 上执行基本搜索的工具。
git-vuln-finder — 从 git 提交消息中发现潜在的软件漏洞
commit-stream — #OSINT 工具，用于通过从 Github 事件 API 实时提取提交日志来查找 Github 存储库
gitrob — GitHub 组织的侦察工具
repo-supervisor — 扫描您的代码以查找安全错误配置，搜索密码和秘密。
GitMiner — 用于在 Github 上进行内容高级挖掘的工具
shhgit 1 - 啊嘘！实时查找 GitHub 机密
检测秘密——一种企业友好的方式来检测和防止代码中的秘密。
rusty-hog — Rust 内置的一套秘密扫描器以提高性能。基于 TruffleHog
耳语——识别硬编码的秘密和危险行为
yar — Yar 是一种用于掠夺组织、用户和/或存储库的工具。
dufflebag — 在暴露的 EBS 卷中搜索秘密
secret-bridge — 监控 Github 中泄露的秘密
earlybird — EarlyBird 是一种敏感数据检测工具，能够扫描源代码存储库中的明文密码违规、PII、过时的加密方法、密钥文件等。
```
## Git
```
GitTools — 一个包含 3 个工具的存储库，用于 pwn'ing 具有可用 .git 存储库的网站
gitjacker — 从配置错误的网站泄漏 git 存储库
git-dumper 1 — 从网站转储 git 存储库的工具
GitHunter — 用于在 Git 存储库中搜索有趣内容的工具
dvcs-ripper 1 — Rip Web 可访问（分布式）版本控制系统：SVN/GIT/HG…
```
## 云安全S3桶
```
S3Scanner — 扫描打开的 AWS S3 存储桶并转储内容
AWSBucketDump — 在 S3 存储桶中查找有趣文件的安全工具
CloudScraper — CloudScraper：枚举目标以搜索云资源的工具。S3 存储桶、Azure Blob、数字海洋存储空间。
s3viewer — 公开开放的 Amazon AWS S3 存储桶查看器
festin — FestIn — S3 存储桶弱点发现
s3reverse — 各种 s3 存储桶的格式转换为一种格式。用于漏洞赏金和安全测试。
mass-s3-bucket-tester — 这会测试 s3 存储桶列表，以查看它们是否启用了目录列表或是否可上传
S3BucketList — 列出请求中找到的 Amazon S3 存储桶的 Firefox 插件
dirlstr — 从 URL 列表中查找目录列表或打开 S3 存储桶
Burp-AnonymousCloud — Burp 扩展执行被动扫描以识别云存储桶，然后测试它们是否存在可公开访问的漏洞
kicks3 — 来自 html、js 和存储桶错误配置测试工具的 S3 存储桶查找器
2tearsinabucket — 枚举特定目标的 s3 存储桶。
s3_objects_check — 有效 S3 对象权限的白盒评估，以识别可公开访问的文件。
s3tk — Amazon S3 的安全工具包
CloudBrute — 很棒的云枚举器
s3cario — 如果 CNAME 是有效的 Amazon s3 存储桶，此工具将首先获取 CNAME，如果不是，它将尝试检查域是否是存储桶名称。
S3Cruze — 适用于渗透测试者的一体化 AWS S3 存储桶工具。
```

## 内容管理系统
```
wpscan — WPScan 是一款免费的、用于非商业用途的黑盒 WordPress 安全扫描器
WPSpider 2 — 用于运行和安排由 wpscan 实用程序支持的 WordPress 扫描的集中式仪表板。
wprecon 1 — WordPress 侦察
CMSmap — CMSmap 是一个 Python 开源 CMS 扫描程序，可自动检测最流行 CMS 的安全漏洞。
joomscan — OWASP Joomla 漏洞扫描程序项目
pyfiscan — 免费的 Web 应用程序漏洞和版本扫描器
```
## JSON_网络令牌
```
jwt_tool — 用于测试、调整和破解 JSON Web 令牌的工具包
c-jwt-cracker — 用 C 编写的 JWT 暴力破解器
jwt-heartbreaker — Burp 扩展，用于检查 JWT（JSON Web 令牌）是否使用来自公共来源的已知密钥
jwtear — 为黑客解析、创建和操作 JWT 令牌的模块化命令行工具
jwt-key-id-injector — 用于检查假设的 JWT 漏洞的简单 python 脚本。
jwt-hack — jwt-hack 是对 JWT 进行黑客/安全测试的工具。
jwt-cracker — 简单的 HS256 JWT 令牌暴力破解器
```
## 子域接管
```
subjack 1 — 用 Go 编写的子域接管工具
SubOver 1 — 强大的子域接管工具
autoSubTakeover — 用于检查 CNAME 是否解析为范围地址的工具。如果 CNAME 解析为非范围地址，则可能值得检查子域接管是否可行。
NSBrute 1 — 用于接管易受 AWS NS Takeover 影响的域的 Python 实用程序
can-i-take-over-xyz 1 — “我可以接管 XYZ 吗？” — 服务列表以及如何使用悬空的 DNS 记录声明（子）域。
cnames — 获取已解析子域的列表并输出任何相应的 CNAME。
subHijack 1 - 劫持被遗忘和错误配置的子域
tko-subs 1 — 一种可以帮助检测和接管具有死 DNS 记录的子域的工具
HostileSubBruteforcer - 此应用程序将对现有子域进行暴力破解，并在 3rd 方主机已正确设置时提供信息。
second-order — 二阶子域接管扫描仪
takeover — 一种用于大规模测试子域接管可能性的工具。
```
## 漏洞扫描器
```
nuclei — Nuclei 是一种基于模板的可配置目标扫描的快速工具，可提供巨大的可扩展性和易用性。
Sn1per - 攻击性安全专家的自动化渗透测试框架
metasploit 框架 1 — Metasploit 框架
nikto — Nikto 网络服务器扫描仪
arachni — Web 应用程序安全扫描器框架
jaeles — 自动化 Web 应用程序测试的瑞士军刀
retire.js 2 — 检测使用已知漏洞的 JavaScript 库的扫描程序
Osmedeus - 用于侦察和漏洞扫描的全自动攻击性安全框架
getsploit — 用于搜索和下载漏洞利用的命令行实用程序
flan — 一个非常可爱的漏洞扫描器
Findsploit — 立即在本地和在线数据库中查找漏洞
BlackWidow — 基于 Python 的 Web 应用程序扫描器，用于收集 OSINT 并模糊目标网站上的 OWASP 漏洞。
backslash-powered-scanner — 查找未知类别的注入漏洞
Eagle - 基于多线程插件的漏洞扫描器，用于大规模检测基于 Web 的应用程序漏洞
cariddi — 获取域列表、抓取 url 并扫描端点、机密、api 密钥、文件扩展名、令牌等……
```
## 未分类
```
JSONBee — 一个准备好使用 JSONP 端点/有效负载来帮助绕过不同网站的内容安全策略 (CSP)。
Cyber Chef——网络瑞士军刀——用于加密、编码、压缩和数据分析的网络应用程序
bountyplz — 来自 Markdown 模板的自动安全报告（HackerOne 和 Bugcrowd 是目前支持的平台）
PayloadsAllTheThings 1 — Web 应用程序安全和 Pentest/CTF 的有用有效负载和绕过列表
bounty-targets-data 1 - 此 repo 包含每小时更新的漏洞赏金平台范围（如 Hackerone/Bugcrowd/Intigriti/etc）的数据转储，这些数据转储符合报告条件
android-security-awesome — android 安全相关资源的集合
awesome-mobile-security — 努力为所有有用的 android 和 iOS 安全相关的东西建立一个单一的地方。
awesome-vulnerable-apps 2 — 令人敬畏的易受攻击的应用程序
XFFenum — X-Forwarded-For [403 禁止] 枚举
httpx — httpx 是一个快速且多用途的 HTTP 工具包，允许使用 retryablehttp 库运行多个探测器，它旨在通过增加线程来保持结果的可靠性。
```
