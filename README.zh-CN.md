# residue-audit · 残迹审计

**从第三方的视角，测量一个藏起来的植入物到底留下了什么。**

![verify](https://github.com/yaorenliang/residue-audit/actions/workflows/ci.yml/badge.svg)

事故报告总以同一句话结尾：*未发现持久化痕迹。*
这句话有两个截然不同的意思，而大多数工具分不清它们。
一个意思是「它不在这儿」；另一个是「它在这儿，只是我们看的方式看不见它」。

这个项目测量的就是这两句话之间的距离。

```
$ residue trace /mnt/image
trace.artifacts     pass     5 artifact(s) matched the marker set
trace.aligned       pass     all 5 artifact(s) are no newer than a sibling
trace.corroborated  pass     every directory holding an artifact also holds a non-artifact sibling
trace.ctime         fail     5 artifact(s) have a ctime newer than every sibling:
                             mtime can be borrowed, ctime cannot
trace.fresh         pass     no artifact carries an mtime within 120s of now
trace.order         fail     5 artifact(s) have a higher inode than every sibling,
                             so creation order is recoverable

summary command=trace status=fail exit=2
```

请再读一遍这段输出。这个植入物做了每一个谨慎操作者都会做的事：
它从邻居那里借了时间戳，它落在本来就有别人的目录里，它躲开了最近两分钟。
**而它仍然在两个地方露着**——因为时间戳可以重写、创建顺序不能重写，
因为改一次 mtime 就会把没人能改回去的 ctime 推到当下。

这就是全部的想法。不是「我们能不能检测到它」，而是
**它藏到哪一层就不再管用，以及别人怎么在不相信我们的前提下把这个结论重做一遍**。

## 三十秒

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

零依赖，Python 3.9+。不联网、不要 root、不离开你的机器。
这个 demo 会造一棵临时树、种下一组合成产物，打印上面那三条判定，
外加两个反例：一棵未对齐的树（必须失败），和一份「恰好一半主机被覆盖」的台账
（一半不是多数，工具会直说）。

## 三个问题

### 一、产物真的融进邻居了吗 —— `residue trace`

写文件的植入物会留下文件，以及文件元数据相对于周围一切的**形状**。
`trace` 读一棵根目录（挂载的镜像、活着的主机、夹具树），把通常被糊成一件事的三个问题分开：

* **对齐**——产物的 mtime 是否不比同目录里最新的非产物邻居更新？任何人拿到可疑主机的第一条命令
  都是 `ls -lt`，对齐就是回答那条命令的。
* **旁证**——这样的邻居到底存不存在？空荡荡的 `/etc/cron.d` 里没有东西可借，
  此时「已对齐」是一个假设穿着判定的衣服。工具返回 `partial`，不是 `pass`。
* **新鲜度**——整棵树是否新到「对齐」这件事失去意义？九十秒前写的、完美对齐的产物，
  依然一眼就是同一批货。

然后两条是地板而不是发现：**ctime**（改 mtime 会推动状态变更时间，用户态设不回去）与
**创建顺序**（inode 单调分配，没有系统调用能重编号）。它们在一个「藏成功」的植入物上都会失败，
而这正是重点——深度有边界，工具把边界画出来，而不是假装它不存在。

### 二、活了多久，其中多少被真正看见 —— `residue dwell`

给一份 ndjson 台账（`{"ts": 1180, "host": "h1", "event": "mine"}`）和一份可选的命中列表，
`dwell` 输出每台主机的跨度、总体分布，以及一个覆盖率。这个覆盖率有三条规则，
因为朴素版本是错的：

* 分母是走到 `deploy` 的主机——只被扫过的主机没有东西可检测，把它算进分母，
  等于允许操作者靠「多扫少投」美化自己的比例；
* 投放前与投放后的命中分开计数——植入物还不存在时规则就响了，那是误报，
  折进同一个比例会让检测栈显得比真实更好；
* 恰好一半不是多数。`> 50.0` 才通过，`50.0` 是 `partial-coverage`，
  而没有提供任何命中时是 `unknown, not zero`。

### 三、一条特征能不能把两次构建聚成一类 —— `residue batch`

给两组从构建里提取的特征，`batch` 两两算 Jaccard 与阈值比较。
有意思的不是「不同」，是「几乎一样」：0.99 的一对，人看两张文件清单觉得是两样东西，
聚类器看是同一件。`threshold - 0.02` 到阈值之间的窄带故意报 `partial`——
那条线附近，再多一次构建就会翻盘。

## 我是怎么发现的

这套检查的起点是一次翻车。植入物把 systemd 单元写进 `/etc/systemd/system`，
再把 mtime 借到与邻居一致。我写了检查器去验证，跑出来是「全部对齐」。

它是错的：客户端二进制被写进 `/usr/local/bin`，那一层对齐失败了却没报错，
而检查器在同一个目录里也找不到「非自家」的邻居，于是拿产物自己当邻居，比完得出「不比邻居新」。

同一次判断，既是识别、又是测量、还是结论。**产物给自己做了旁证。**

修法不是补一个 if，是把三件事拆开：识别（启发式，必须标注）、测量（元数据，谁都能重做）、
判定（一条可以被别人推翻的判据）。拆开之后，第一个冒出来的事实是：
在没有邻居的目录里，「对齐」不是一个结论，是一个假设。

于是有了 `trace.corroborated` 这一条；有了把本地测量结果用 `stat(1)` 重算一遍的
`tests/cross_check.sh`；也有了一份写明「我查不出什么」的文档。

## 为什么会有这个仓

这个位置不是空的，但是偏的。时间戳取证是成熟的——NTFS 上的
`$STANDARD_INFORMATION` 与 `$FILE_NAME`、Windows 侧的工具链与公开论文；
驻留时间是到处被**命名**、却没人**计算**的——每家厂商都有 MTTD 的词条，没有一家把算术交出来；
跨构建相似度则躺在商业聚类产品里。

缺的是中间那件事：**一个小的、零依赖的、可复现的方式，去检验「我的植入物藏得很好」这句话。**
不是扫描器，不是框架，是一次审计——响应者凌晨三点能指着一个镜像跑，
研究者能指着一篇论文的表格跑。

所以设计约束很奇怪：每一个数字都必须能被**不信任这份代码的人**重算出来。
这就是为什么检查被拆成「识别」与「测量」，为什么 `tests/cross_check.sh` 要用 shell 把计数
再算一遍、不一致就红。

## 边界

引用任何数字之前，请先读 [docs/limits.zh-CN.md](docs/limits.zh-CN.md)。短版：

* **看不见内存。** `/proc/<pid>/exe` 背后的二进制在文件被删后仍可读，本工具不读 `/proc` 下任何东西。
* **目录还没检查。** 写文件会更新父目录的 mtime **和** ctime，而 ctime 设不了。
  这是本工具最可能在一台人眼一看就脏的主机上给出 `pass` 的地方——已知缺口，写在明处。
* **`ctime` 只证明「比邻居晚改」**，不证明是攻击者改的：一次包升级留下同样的信号。
* **inode 顺序是地板。** 删除后的 inode 复用会让它变钝。
* **识别是启发式的。** 持久化机制不像 systemd 的植入物不会被认领，而未被认领的产物根本不会被测量。
  工具对这类文件的沉默，不是一个发现。
* **`batch` 只看见一个投影。** 低分是「字符串没能把它们分开」，不是「不可关联」的证明。

## 自己验一遍

```bash
make test     # 15 条单测：golden 契约 + 负控
make cross    # L3：用 stat(1) 把同一批数字重算一遍
make verify   # 两者
make lab      # L2：同一套夹具在真实 ext4 客机里，无外网，首次启动后约 90 秒
```

四层验证，后两层才是要紧的：

| 层 | 它证明什么 | 怎么做 |
|---|---|---|
| L0 | 判定确实是我们说的那个 | 夹具 → golden JSON，逐字段比对 |
| L1 | 这条检查有能力失败 | 每条检查配一个必须不通过的输入 |
| L2 | 结论在 ext4 上成立，不只在 macOS 临时目录里成立 | QEMU 客机，`-netdev user,restrict=on` |
| L3 | 这个数字经得起另一种实现 | shell + `stat(1)` 重算，与我们的结果对差 |

没有 L1，「通过了」等于「没测」；没有 L3，「复算过」等于「同一个程序说了两遍同样的话」。

## 范围

在范围内：文件系统元数据一致性、驻留时间与检测覆盖的度量、跨构建相似度评分。

永久不在范围内：投放、横向移动、植入持久化、凭证访问，或任何作用于「它没有被指向的主机」的东西。
lab 里的「植入物」是五件写文本文件就退出的夹具；客机无外网，仓库只读挂载。

## 文档

* [docs/method.zh-CN.md](docs/method.zh-CN.md) —— 每条检查测什么、为什么长这样
* [docs/limits.zh-CN.md](docs/limits.zh-CN.md) —— 它看不见什么，按检查分列
* [docs/essay.zh-CN.md](docs/essay.zh-CN.md) —— 长文《我怎么验证一个木马到底藏得多深》

## 许可

MIT，见 [LICENSE](LICENSE)。