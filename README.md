# FileSecurity

这是我用 Java 8 编写的数据加密软件，可以将它打包成可执行的 jar 文件。

可以通过启动参数加密或解密指定文件或目录。

```bash
usage: FileSecurity [-d] [-dest <file path>] [-e] [-h] [-src <file path>]
       [-v]
 -d,--decrypt                      解密文件
 -dest,--destination <file path>   目标目录
 -e,--encrypt                      加密文件
 -h,--help                         帮助信息
 -src,--source <file path>         源文件路径或指定文件
 -v,--version                      软件版本
```

其中 src 可以是指定文件也可以是目录，如果是目录会变量目录下的所有文件；dest 必须是目录，不能是文件。

## 命令演示

**加密命令**
```bash
java -jar .\filesecurity-1.0.jar -e -source=D:\xxxx -destination=D:\xxxx_bak
```

**加密命令**
```bash
java -jar .\filesecurity-1.0.jar -d -source=D:\xxxx_bak -destination=D:\xxxx
```

> 注意："xxxx" 可以是任意名称。
> 
> 还有就是 src 和 dest 目前只支持一个参数，如果有多个只会使用第一个。

## 测试结果

使用了 Java 随机文件读取，使用多线程，加密 4G 的文件用了 8 分钟。
