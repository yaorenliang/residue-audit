# residue-audit · 残迹审计

**从第三方的位置，测量一个藏起来的植入物到底留下了什么。**

事故报告常常以同一句话结尾：未发现持久化痕迹。
这句话有两个意思，工具很少区分。一个是它不在这台机器上；
另一个是它在这台机器上，而我们看的方式看不见它。这个项目测量两者的距离。

```
$ residue demo    # 第 1 段，共 6 段
### borrowed. artifacts written last, mtimes borrowed from a neighbour
trace.artifacts        pass     5 artifact(s) matched the marker set
                                  <root>/etc/cron.d/kworkers-updater marker=content:kworker
                                  <root>/etc/systemd/system/zz-bridge.service marker=unit:marker
                                  <root>/etc/systemd/system/zz-harvest.service marker=unit:marker
                                  <root>/usr/libexec/kworker marker=marker:KillSignal=SIGCONT
                                  <root>/usr/local/bin/bridge-client-x marker=unit:execstart
trace.aligned          pass     all 5 artifact(s) are no newer than a sibling
                                  <root>/etc/cron.d neighbour_cap_ms=1609459200000
                                  <root>/etc/systemd/system neighbour_cap_ms=1609459200000
                                  <root>/usr/libexec neighbour_cap_ms=1609459200000
                                  <root>/usr/local/bin neighbour_cap_ms=1609459200000
trace.corroborated     pass     every directory holding an artifact also holds a non-artifact sibling
trace.ctime            fail     5 artifact(s) have a ctime newer than every sibling: mtime can be borrowed, ctime cannot
                                  <root>/etc/cron.d/kworkers-updater ctime_vs_cap=newer
                                  <root>/etc/systemd/system/zz-bridge.service ctime_vs_cap=newer
                                  <root>/etc/systemd/system/zz-harvest.service ctime_vs_cap=newer
                                  <root>/usr/libexec/kworker ctime_vs_cap=newer
                                  <root>/usr/local/bin/bridge-client-x ctime_vs_cap=newer
trace.directory_ctime  partial  4 holding director(y/ies) changed after the artifacts they hold: a directory mtime/ctime is the usual hiding place, and it dates the assembly, not the intent
                                  <root>/etc/cron.d dir_ctime_vs_oldest_mtime=<now> > 1609459200000
                                  <root>/etc/systemd/system dir_ctime_vs_oldest_mtime=<now> > 1609459200000
                                  <root>/usr/libexec dir_ctime_vs_oldest_mtime=<now> > 1609459200000
                                  <root>/usr/local/bin dir_ctime_vs_oldest_mtime=<now> > 1609459200000
trace.fresh            pass     no artifact carries an mtime within 120s of now
trace.order            fail     5 artifact(s) have a higher inode than every sibling, so creation order is recoverable
                                  <root>/etc/cron.d/kworkers-updater inode_order=newest
                                  <root>/etc/systemd/system/zz-bridge.service inode_order=newest
                                  <root>/etc/systemd/system/zz-harvest.service inode_order=newest
                                  <root>/usr/libexec/kworker inode_order=newest
                                  <root>/usr/local/bin/bridge-client-x inode_order=newest
trace.readable         pass     every scanned path was read; no verdict rests on a skipped path

absolute_links=0
aligned=5
artifacts=5
ctime=5
errors=[]
fresh=0
leaks=0
order=5
root=<root>
scan=["etc/systemd/system", "etc/cron.d", "usr/libexec", "usr/local/bin"]
truncated_files=0
uncorroborated=0
weak_claims=0
weak_paths=[]

summary command=trace status=fail exit=2
note: order and ctime still fail here. utimensat rewrites a timestamp;
      nothing user-space can rewrite the inode number or the ctime.
```

`make docs-sample` 会打印本 README 引用的六段 demo（上面这段是第 1 段），
外加 `--json` 的形状，所以这段文字可以被 diff，而不是被相信。
`tests/readme_sample.py` 打印上面这段，`tests/test_docs.py` 逐行 diff，引用不会
悄悄过期：只有两处是替换的——`<root>` 是 demo 在 `$TMPDIR` 下造的临时树，
`<now>` 是 `directory_ctime` 背后那个墙钟数字。其余全是工具自己的输出。

这段输出里，植入物做了谨慎操作者会做的全部动作：从邻居那里借来时间戳，
落在本来就有别人的目录里，避开最近两分钟。它在三个地方仍然露着：
时间戳可以重写，创建顺序不能重写；改一次 mtime，会把没人能改回去的 ctime 推到当下；
而容纳它的目录，在文件落日期之后还被改动过。

### 退出码是什么意思

| 码 | 含义 | 门禁该怎么读 |
|---|---|---|
| 0 | `pass` | 跑过的检查什么都没找到 |
| 1 | `partial` | 有东西测不了，不等于干净 |
| 2 | `fail` | 至少一条检查找到了残迹 |
| 3 | `skip` | 什么都没匹配上，这次审计没有发生 |
| 4 | 工具故障 | 用法错、输入读不出、崩溃 —— 永远不是判定 |

4 之所以存在，是因为 1 和 2 都是判定。码位没拆开之前，打错一个旗标（argparse 的 2）
和一次未捕获异常（Python 的 1）会被读成「发现残迹」和「测不了」，
于是写成 `if exit == 2` 的门禁会因为手滑响起来。

所以问题不是「能不能检测到它」，而是它藏到哪一层就不再管用，
以及别人怎么在不相信这份代码的前提下，把结论重做一遍。

## 三十秒

```bash
git clone https://github.com/yaorenliang/residue-audit
cd residue-audit
make demo
```

零依赖，Python 3.9 以上。不联网，不需要 root，不读写仓库之外的路径。
demo 会造几棵一次性临时树，打印六段：上面那棵借 mtime 的树；一棵合成树能达到的最好结果
（对齐、ctime、order 全过，但容纳它的目录仍然暴露了组装时间）；一段真正通过的覆盖率；
一份恰好一半主机被覆盖的台账；两棵聚成一类的构建；两棵聚不成一类的构建。
三种判定都会出现，而且 demo **按判定退出**，所以哪天它烂成「什么都失败」，那是红构建，不是截图。

## 在真主机上它说什么

lab 起一台标准 Ubuntu 24.04，无外网，审计两次。

**识别。** 先用宽规则（任何单元 ExecStart= 提到的任何文件都算自家的）跑：
认领 13 个文件，其中 5 个是我们的，精度 38%。另外 8 个是 packagekitd、boltd、
qmi-proxy、packagekit-direct、pk-debconf-helper、pk-offline-update、mbim-proxy
和 /etc/cron.d/e2scrub_all，全由正常安装的单元启动。
改成锚在带标记的单元上、再顺着 ExecStart= 往外走：认领 5 个，误报 0 个，
另外 8 个文件记为弱认领，不参与审计。想恢复旧规则用 `--broad`，代价自己承担。

**地板。** 收窄后的那次跑，5 个产物全部对齐，泄漏 0 个，结论仍然 fail，
卡在 ctime 与 order 两条，目录 ctime 那条报 partial。这不是夹具的问题，
是「最多能藏多深」的答案，而且它带数字。

13 = 5 个认领 + 8 个弱认领，所以宽规则的精度是 5/13 = 38%。lab 把
`LAB_ROOT_OURS=5` 和 `LAB_ROOT_WEAK=8` 打进 `out/lab-console.log`；算术只占一行，
因为读者不该被迫相信一个百分比。

## 三个问题

### 一、产物融进邻居了吗：`residue trace`

写文件的植入物留下两种东西：文件本身，以及这些文件的元数据相对周围一切呈现的形状。
`trace` 读一个根目录（挂载的镜像、活着的主机、夹具树），把通常被混成一件事的三个问题拆开。

* **对齐**：产物的 mtime 是否不比同目录里最新的非产物邻居更新。
  拿到可疑主机的第一条命令是 `ls -lt`，对齐回答的就是这条命令。
* **旁证**：这样的邻居到底存不存在。空的 `/etc/cron.d` 里没有东西可借，
  这时「已对齐」只是假设，工具返回 `partial`，不返回 `pass`。
* **新鲜度**：整棵树是不是新到让对齐失去意义。九十秒前写的文件，对齐得再好也属于同一批货。

后面几条是地板与线索，不是发现。**ctime**：改 mtime 会推动状态变更时间，用户态设不回去。
**创建顺序**：inode 单调分配，没有系统调用能重新编号。
一个「藏成功」的植入物在这两条上都会失败。深度有边界，工具把边界写出来。
**容纳它的目录**：文件落日期之后目录还被改动过，报 `trace.directory_ctime` partial ——
目录日期只能说明「这批东西是什么时候组装起来的」，说明不了意图，一次包升级同样会动它，
所以它只能当线索，不能单独构成发现。**可读性**：扫不进去的路径进 `facts.errors`，
并把 `trace.readable` 降成 partial；从前 `chmod 000` 能让整次审计变成「没有东西可审」。

### 二、活了多久，其中多少被看见：`residue dwell`

输入是一份 ndjson 台账（`{"ts": 1180, "host": "h1", "event": "mine"}`）和一份可选的命中列表。
输出是每台主机的跨度、总体分布和一个覆盖率。覆盖率有几条规则，因为朴素算法是错的：

* 分母是走到 `deploy` 的主机。只被扫过的主机没有东西可检测，
  算进分母就等于允许操作者靠多扫少投抬高比例。
* 投放前和投放后的命中分开计数。植入物还不存在时规则响了，那是误报，
  折进同一个比例会让检测栈显得比实际更好。
* 恰好一半不是多数。`> 50.0` 才通过，`50.0` 是 `partial-coverage`，
  没有提供命中数据时是 `unknown, not zero`。零是测量结果，没看不是。
* 另一个分母照样打印。`hit_rate_all_hosts` 回答「在我们观察到的所有主机里占多少」，
  读者能自己看出两个比例差多远，而不是只拿到好看的那个。
* 事件类型不在 `{deploy, mine, scan}` 里时会被点名，不会被吸收：上游改一次词表，分母就会悄悄变小，
  而任何以缩小后的分母算出的比例都会上升 —— `unknown_events` 报数，`dwell.schema` 报 partial。
* 命中一台台账从没投放过的机器，会进 `hits_unmatched`，而不是被丢掉、
  它的规则计数却继续出现在输出里。

### 三、一条特征能不能把两次构建聚成一类：`residue batch`

输入两组特征，两两算 Jaccard，与阈值比较。有意思的不是「不同」，
是「几乎一样」：0.99 的一对，人看两张文件清单觉得是两样东西，聚类器看是同一件。
`threshold - 0.02` 到阈值之间故意报 `partial`，那条线附近再多一次构建就会翻盘。
挪这条线的是 `--threshold`，挪了就要说明用的是哪一个。

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
* **目录日期是线索，不是证据。** `trace.directory_ctime` 在「容纳产物的目录晚于里面文件的日期」时报
  `partial`：它定的是组装时间，不是意图，所以不能单独构成发现。一次包升级同样会动这个目录。
* **读不进去的路径会被报出来，不会被当成空目录。** 扫不了的目录进 `facts.errors`，
  并把 `trace.readable` 降成 partial。这条以前不存在：对一个扫描目录 `chmod 000`，
  审计会返回「没有东西可审」，对失败一字不提。
* **`--scan` 缩小的是「在哪儿登记 claim」，不是「锚从哪儿来」。** 锚来自工具能触达的、
  带 marker 的 unit（含默认目录）：读一个 unit 只为知道植入体启动哪个二进制，本身不登记
  任何 claim。所以 `--scan etc/cron.d` 仍能找到点名我们二进制的 cron 条目，而 `etc/cron.d`
  之外依旧不产生 claim。
* **`demo --json` 保证一条流是机器可读的。** 六段是散文，所以带 `--json` 时它们走 stderr，
  stdout 只留报告文档本身。
* **`ctime` 只说明文件比邻居晚改**，不说明是谁改的。一次包升级留下同样的信号。
* **inode 顺序是地板。** 删除后的 inode 复用会让它变钝。
* **识别是启发式的。** 持久化机制不像 systemd 的植入物不会被认领，未被认领的产物不会被测量。
  工具对这类文件的沉默，不算发现。
* **`batch` 只看见一个投影。** 低分说明字符串没能把它们分开，不是不可关联的证明。

## 自己验一遍

```bash
make test     # 单测：golden 契约 + 负控
make cross    # L3：用 stat(1) 把同一批数字重算一遍
make cov      # 行覆盖率，只用标准库，总额与模块两级地板
make verify   # 上面三项
make lab      # L2：同一套夹具在真实 ext4 客机里，无外网
```

四层验证，另加一层地板。中间两层最要紧：

| 层 | 它证明什么 | 怎么做 |
|---|---|---|
| L0 | 判定确实是我们说的那个 | 夹具生成 golden JSON，逐字段比对 |
| L1 | 这条检查有能力失败 | 每条检查配一个必须不通过的输入：8 条检查、8 个负控，另加一例「认得出但读不进去」 |
| L2 | 结论在 ext4 上成立，不只在 macOS 临时目录里成立 | QEMU 客机，`-netdev user,restrict=on` |
| L3 | 数字经得起另一种实现 | shell + `stat(1)` 重算，与我们的结果对差 |
| 地板 | 测试覆盖了它声称覆盖的东西 | `make cov` 低于总额地板就红；任一模块比 `tests/coverage_baseline.json` 记录值低 2 个点以上也红 |

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
