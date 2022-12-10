# Java CodeAudit Study Notes
# Java EE 基础知识
# 1.  java反射机制
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


# OWASP Top 10 漏洞的代码审计
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
**ProcessBuilder()和Runtime.getRuntime.exec()本质上一样。**
