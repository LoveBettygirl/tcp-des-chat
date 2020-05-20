# tcp-des-chat

网络安全技术编程作业 #1 （基于 DES 加密的 TCP 聊天程序，v1.0）和 #2 （基于 RSA 算法自动分配密钥的加密聊天程序，v2.0 & v3.0）

使用的是 Java 语言，其中任何实现都可能有 bug ，有问题请多指教。

由于两个作业属于同一主题，故把新的作业内容和旧的作业内容整合进同一个 repo 中。

## 编程环境

- JDK 9.0.4 x64 （可兼容 JRE 1.8）
- Eclipse，Version: Photon Release (4.8.0)

（我也不想用 JDK9 ，兼容性各种不好，但是以前的 JDK 版本的 Swing 又不支持我电脑的高分屏，只能妥协了）

## 目录结构

```
tcp-des-chat/
├─LICENSE
├─README.md
├─v1.0
│  ├─report.pdf  # 实验1报告
│  ├─DESChat.jar  # 可执行jar包
│  └─DESChat
│      ├─bin
│      │  ├─com
│      │  │  └─deschat
│      │  │      ├─client
│      │  │      ├─des
│      │  │      ├─mainprg
│      │  │      └─server
│      │  └─img
│      └─src
│          ├─com
│          │  └─deschat
│          │      ├─client
│          │      ├─des
│          │      ├─mainprg
│          │      └─server
│          └─img
├─v2.0
│  ├─DESChatV2.jar  # 可执行jar包
│  └─DESChatV2
│      ├─bin
│      │  ├─com
│      │  │  └─deschatv2
│      │  │      ├─alg
│      │  │      ├─client
│      │  │      ├─mainprg
│      │  │      └─server
│      │  └─img
│      └─src
│          ├─com
│          │  └─deschatv2
│          │      ├─alg
│          │      ├─client
│          │      ├─mainprg
│          │      └─server
│          └─img
└─v3.0
    ├─report.pdf  # 实验2报告
    ├─DESChatV3.jar  # 可执行jar包
    └─DESChatV3
        ├─bin
        │  ├─com
        │  │  └─deschatv3
        │  │      ├─alg
        │  │      ├─client
        │  │      ├─mainprg
        │  │      └─server
        │  └─img
        └─src
            ├─com
            │  └─deschatv3
            │      ├─alg
            │      ├─client
            │      ├─mainprg
            │      └─server
            └─img
```

## 功能说明

### v1.0

- [x] 手动实现了 DES 算法（不是使用`javax.crypto.Cipher`类）
- [x] 实现了 TCP **单个**服务器和**多个**客户端的通信，客户端套接字使用了`java.net.Socket`类，服务器端监听套接字使用了 `java.net.ServerSocket`类
- [x] 实现了 DES 对聊天内容的加密和解密
- [x] 为每个客户端随机分配一个初始密钥
- [x] 支持中文的 DES 加密和解密
- [x] 实现了客户端和服务器聊天的可视化（使用了 Swing ）
- [x] 使用了多线程，无论是客户端还是服务器都可以随时给对方发送消息，无需等待对方回复。客户端还是服务器的任何一方都可以先开始聊天。

### v2.0

- [x] 增加了使用 `java.math.BigInteger` 类实现的 RSA 算法模块，不借助此类中与 RSA 相关的函数（例如 `probablePrime()` 和 `modPow()`），并可自定义产生素数的长度
- [x] 按照实验要求将随机产生 DES 密钥的模块移动至客户端
- [x] 实现 DES 密钥使用 RSA 公钥加密、RSA 私钥解密
- [x] DES 密钥的交互方式从明文交互改为：服务器端先向客户端发送 RSA 公钥，客户端使用 RSA 公钥加密随机生成的 DES 密钥并发送给服务器，服务器使用 RSA 私钥解密出 DES 密钥，从而增加通信的安全性
- [x] 可视化界面中不再显示 DES 密钥，转为在命令行中显示，增加通信的安全性
- [x] 优化了客户端丢失连接后的可视化界面输出和命令行输出

### v3.0

- [x] 使用Java NIO （`java.nio`）框架改写的异步非阻塞 TCP 通信模块，减少了服务器端的线程开销。客户端信道使用了 `java.nio.channels.AsynchronousSocketChannel`，服务器端监听信道使用了 `java.nio.channels.AsynchronousServerSocketChannel`

## 其他事项

- 对于 RSA 的大素数生成，本程序使用多次执行 Miller-Rabin 算法的方式作为素性检测的方式。为了保证素性检测的精度，执行 Miller-Rabin 算法的次数请自行决定（尽量不要太少）
- 由于本程序中 RSA 的使用范围仅限于加密 64 位的 DES 密钥，如果 RSA 密钥值太小可以将 `bitLen`参数设大，因此没有考虑 RSA 分段加密/解密的问题