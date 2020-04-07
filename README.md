# tcp-des-chat

网络安全技术编程作业 #1 —— 基于DES加密的TCP聊天程序

使用的是 Java 语言，其中的 DES 算法和 TCP 通信的部分可能有些瑕疵（但是最终运行的效果没有什么违和感），有问题请多指教。

报告用的是老师给的模板，不是自己的模板。不知道是不是模板限制了我的文采，反正好一个流水账。。。

## 编程环境

- JDK 9.0.4 x64
- Eclipse，Version: Photon Release (4.8.0)

（我也不想用 JDK9 ，兼容性各种不好，但是以前的 JDK 版本的 Swing 又不支持我电脑的高分屏，只能妥协了）

## 功能说明

:ballot_box_with_check: 手动实现了 DES 算法（不是使用`javax.crypto.Cipher`类）

:ballot_box_with_check: 实现了 TCP **单个**服务器和**多个**客户端的通信，使用了`java.net.Socket`和`java.net.ServerSocket`类

:ballot_box_with_check: 实现了 DES 对聊天内容的加密和解密

:ballot_box_with_check: 为每个客户端随机分配一个初始密钥

:ballot_box_with_check: 支持中文的加密和解密

:ballot_box_with_check: 实现了客户端和服务器聊天的可视化（使用了 Swing ）

:ballot_box_with_check: 使用了多线程