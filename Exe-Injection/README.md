

inject "arbitrary" PE file into other process memory, then execute it


目标进程只能是32bit进程。而且注入成功之后，线程退出，整个进程也会退出，所以最好新开一个空闲的进程，比如python的解释器窗口（32-bit），这里python进程的父进程是explorer.exe。

之后通过tasklist查看python.exe的进程pid。

以pid为参数运行injectEXE.exe，会有弹窗。

```
injectEXE.exe [pid]
```
