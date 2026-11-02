# residue-audit · 残迹审计

**从第三方的位置，测量一个藏起来的植入物到底留下了什么。**

事故报告常常以同一句话结尾：未发现持久化痕迹。
这句话有两个意思，工具很少区分。一个是它不在这台机器上；
另一个是它在这台机器上，而我们看的方式看不见它。这个项目测量两者的距离。

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

这段输出里，植入物做了谨慎操作者会做的全部动作：从邻居那里借来时间戳，
落在本来就有别人的目录里，避开最近两分钟。它在两个地方仍然露着。
时间戳可以重写，创建顺序不能重写；改一次 mtime，会把没人能改回去的 ctime 推到当下。

所以问题不是「能不能检测到它」，而是它藏到哪一层就不再管用，
以及别人怎么在不相信这份代码的前提下，把结论重做一遍。

## 三十秒

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

零依赖，Python 3.9 以上。不联网，不需要 root，不读写仓库之外的路径。
demo 会造一棵临时树，种下一组合成产物，打印上面那三条判定，另外给两个反例：
一棵未对齐的树（必须失败），一份恰好一半主机被覆盖的台账（一半不是多数，工具照实说）。

## 在真主机上它说什么

lab 起一台标准 Ubuntu 24.04，无外网，审计两次。

**识别。** 先用宽规则（任何单元 ExecStart= 提到的任何文件都算自家的）跑：
认领 13 个文件，其中 5 个是我们的，精度 38%。另外 8 个是 packagekitd、boltd、
qmi-proxy、packagekit-direct、pk-debconf-helper、pk-offline-update、mbim-proxy
和 /etc/cron.d/e2scrub_all，全由正常安装的单元启动。
改成锚在带标记的单元上、再顺着 ExecStart= 往外走：认领 5 个，误报 0 个，
另外 8 个文件记为弱认领，不参与审计。想恢复旧规则用 `--broad`，代价自己承担。

**地板。** 收窄后的那次跑，5 个产物全部对齐，泄漏 0 个，结论仍然 fail，
卡在 ctime 与 order 两条。这不是夹具的问题，是「最多能藏多深」的答案，而且它带数字。

## 三个问题

### 一、产物融进邻居了吗：`residue trace`

写文件的植入物留下两种东西：文件本身，以及这些文件的元数据相对周围一切呈现的形状。
`trace` 读一个根目录（挂载的镜像、活着的主机、夹具树），把通常被混成一件事的三个问题拆开。

* **对齐**：产物的 mtime 是否不比同目录里最新的非产物邻居更新。
  拿到可疑主机的第一条命令是 `ls -lt`，对齐回答的就是这条命令。
* **旁证**：这样的邻居到底存不存在。空的 `/etc/cron.d` 里没有东西可借，
  这时「已对齐」只是假设，工具返回 `partial`，不返回 `pass`。
* **新鲜度**：整棵树是不是新到让对齐失去意义。九十秒前写的文件，对齐得再好也属于同一批货。

后面两条是地板，不是发现。**ctime**：改 mtime 会推动状态变更时间，用户态设不回去。
**创建顺序**：inode 单调分配，没有系统调用能重新编号。
一个「藏成功」的植入物在两条上都会失败。深度有边界，工具把边界写出来。

### 二、活了多久，其中多少被看见：`residue dwell`

输入是一份 ndjson 台账（`{"ts": 1180, "host": "h1", "event": "mine"}`）和一份可选的命中列表。
输出是每台主机的跨度、总体分布和一个覆盖率。覆盖率有三条规则，因为朴素算法是错的：

* 分母是走到 `deploy` 的主机。只被扫过的主机没有东西可检测，
  算进分母就等于允许操作者靠多扫少投抬高比例。
* 投放前和投放后的命中分开计数。植入物还不存在时规则响了，那是误报，
  折进同一个比例会让检测栈显得比实际更好。
* 恰好一半不是多数。`> 50.0` 才通过，`50.0` 是 `partial-coverage`，
  没有提供命中数据时是 `unknown, not zero`。零是测量结果，没看不是。

### 三、一条特征能不能把两次构建聚成一类：`residue batch`

输入两组特征，两两算 Jaccard，与阈值比较。有意思的不是「不同」，
是「几乎一样」：0.99 的一对，人看两张文件清单觉得是两样东西，聚类器看是同一件。
`threshold - 0.02` 到阈值之间故意报 `partial`，那条线附近再多一次构建就会翻盘。

## 我是怎么发现的

这套检查的起点是一次翻车。植入物把 systemd 单元写进 `/etc/systemd/system`，
再把 mtime 借到与邻居一致。我写了检查器验证，跑出来是「全部对齐」，而它是错的：
客户端二进制写在 `/usr/local/bin`，那一层对齐失败却没人报错，
检查器在那个目录里也找不到非自家邻居，于是拿产物自己当邻居，比完得出「不比邻居新」。

同一次判断，既是识别，又是测量，还是结论。产物给自己做了旁证。

修法不是补一个 if，是把三件事拆开：识别（启发式，必须标注）、测量（元数据，谁都能重做）、
判定（可以被别人推翻的判据）。拆开之后第一个冒出来的事实是：
没有邻居的目录里，「对齐」不是结论，是假设。

于是有了 `trace.corroborated`，有了用 `stat(1)` 重算一遍的 `tests/cross_check.sh`，
也有了一份写明「我查不出什么」的文档。

## 为什么会有这个仓

这个位置偏空。时间戳取证成熟：NTFS 上的 `$STANDARD_INFORMATION` 与 `$FILE_NAME`、
Windows 侧的工具链、磁盘层时间篡改的公开论文。驻留时间到处被命名，却很少有人把算术交出来；
每家厂商都有 MTTD 词条，没有一家附带计算器。跨构建相似度躺在商业聚类产品里。

缺的是中间那件事：一个小的、零依赖的、可复现的方式，用来检验「我的植入物藏得很好」这句话。
不是扫描器，也不是框架，是一次审计。响应者凌晨三点能指着一个镜像跑，
研究者能指着一篇论文的表格跑。

所以设计约束有点怪：每个数字都必须能被不信任这份代码的人重算出来。
检查因此被拆成识别与测量两段；`tests/cross_check.sh` 用 shell 把计数再算一遍，不一致就红。

## 边界

引用数字之前先读 [docs/limits.zh-CN.md](docs/limits.zh-CN.md)。短版如下。

* **看不见内存。** `/proc/<pid>/exe` 背后的二进制在文件被删后仍可读，本工具不读 `/proc`。
* **目录还没检查。** 写文件会更新父目录的 mtime 和 ctime，ctime 设不了。
  这是本工具最可能在一块人眼一看就脏的主机上给出 `pass` 的地方，已知缺口，写在明处。
* **`ctime` 只说明文件比邻居晚改**，不说明是谁改的。一次包升级留下同样的信号。
* **inode 顺序是地板。** 删除后的 inode 复用会让它变钝。
* **识别是启发式的。** 持久化机制不像 systemd 的植入物不会被认领，未被认领的产物不会被测量。
  工具对这类文件的沉默，不算发现。
* **`batch` 只看见一个投影。** 低分说明字符串没能把它们分开，不是不可关联的证明。

## 自己验一遍

```bash
make test     # 16 条单测：golden 契约 + 负控
make cross    # L3：用 stat(1) 把同一批数字重算一遍
make verify   # 两者
make lab      # L2：同一套夹具在真实 ext4 客机里，无外网
```

四层验证，后两层更要紧：

| 层 | 它证明什么 | 怎么做 |
|---|---|---|
| L0 | 判定确实是我们说的那个 | 夹具生成 golden JSON，逐字段比对 |
| L1 | 这条检查有能力失败 | 每条检查配一个必须不通过的输入 |
| L2 | 结论在 ext4 上成立，不只在 macOS 临时目录里成立 | QEMU 客机，`-netdev user,restrict=on` |
| L3 | 数字经得起另一种实现 | shell + `stat(1)` 重算，与我们的结果对差 |

没有 L1，「通过」等于「没测」；没有 L3，「复算过」等于「同一个程序说了两遍同样的话」。

## 范围

范围内：文件系统元数据一致性、驻留时间与检测覆盖的度量、跨构建相似度评分。

永久不在范围内：投放、横向移动、植入持久化、凭证访问，以及任何作用于「它没有被指向的主机」的东西。
lab 里的植入物是五件写文本文件就退出的夹具，客机无外网，仓库只读挂载。

## 文档

* [docs/method.zh-CN.md](docs/method.zh-CN.md)：每条检查测什么，为什么长这样
* [docs/limits.zh-CN.md](docs/limits.zh-CN.md)：它看不见什么，按检查分列
* [docs/essay.zh-CN.md](docs/essay.zh-CN.md)：长文《我怎么验证一个木马到底藏得多深》

## 许可

MIT，见 [LICENSE](LICENSE)。
