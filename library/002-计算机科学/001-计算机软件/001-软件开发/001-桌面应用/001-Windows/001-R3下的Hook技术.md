# R3下的Hook技术

> 标签： Windows Hook Inline IAT DLL 劫持

## 项目信息

### 基本内容

 - 项目编号：FHO-0001
 - 项目等级：**初级**
 - 内容分类：明理 记录
 - 项目简介：*Windows R3下的Hook技术汇总*
 - 最后更新：2018-07-26 08:10:00

### 依赖知识

 1. 汇编语言与C语言[^1]
 2. Visual Studio的使用[^2]
 3. [DLL文件介绍](http://www.baidu.com)
 3. [Windows R3下的代码注入技术](http://www.baidu.com)

### 存储方式
 
  - [x] 原始文档
  - [x] 知识库
  - [ ] 记忆库
 
## 核心知识

### 一、Inline Hook

#### 简介

Inline Hook应该说是最朴素思想的一种Hook技术。通过直接修改原代码（是原代码不是源代码，之后用 **原函数** 的说法替换）跳转到自己的逻辑中执行。之后有可能跳回来，也有可能就此不管，也有可能在某个时间点还原被Hook的代码，一切随作者心意。之所以称之为Inline，也正是因为**这种Hook方式直接改变了原函数的运行逻辑**，就如同原函数中的一个内联函数一般，故如此命名。
 
#### Inline Hook的流程

实现的手法固然各有差异，流程一般如下：

```flow
st=>start: 编写用于替换原函数的Hook函数【Hook函数】
o1=>operation: 编写跳转到【Hook函数】的代码【跳转Code】（一般由汇编实现）
o2=>operation: 寻找原函数所在内存
o3=>operation: 解除原函数所在内存的读写保护
o4=>operation: 保存原函数入口处若干字节（由具体跳转代码的字节数决定）的代码【原入口代码】
o5=>operation: 修改【原入口代码】为【跳转代码】
o6=>operation: 恢复原函数所在内存的读写保护
o6=>operation: 函数被调用……
o7=>operation: 不需要继续Hook时，用【原入口代码】还原【跳转Code】
ep=>end: 结束

st->o1->o2->o3->o4->o5->o6->o7->ep
```

接下来用一案例结合代码实际演示Inline Hook技术。

#### Inline Hook实战

通过对 *Windows任务管理器* 的`TerminateProcess`函数进行Inline Hook，使其不能关闭其他进程。

在正式开始之前，要先说明几个容易踩坑的地方。

[^1]:所需的C语言与汇编语言知识

[^2]:Visual Studio的基础操作