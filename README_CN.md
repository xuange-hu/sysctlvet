# sysctlvet

[![tests](https://img.shields.io/badge/tests-162-brightgreen)](https://github.com/xuange-hu/sysctlvet/actions)
[![python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/xuange-hu/sysctlvet/blob/main/pyproject.toml)

**零依赖的内核参数（sysctl）审计器。**
它先还原 `sysctl.d` 加载顺序里**哪一行真正生效**，再告诉你哪些加固被后面的文件悄悄改了回去。
三遍扫描——单项设置、危险组合、文件间关系——每条结论都指向具体行号与原始文本。

```console
$ sysctlvet scan /etc/sysctl.conf /etc/sysctl.d/
MEDIUM   SYS301  hardening kernel.randomize_va_space = 2 is silently reverted: /etc/sysctl.conf:12 sets it back to 0
         at /usr/lib/sysctl.d/50-default.conf:3 (offset 96, len 29)
         saw: kernel.randomize_va_space = 2
         fix: Delete the losing line or change the winning file; one key must have one owner.
HIGH     SYS109  kernel.randomize_va_space = 0 weakens or disables ASLR
         at /etc/sysctl.conf:12 (offset 240, len 28)
         saw: kernel.randomize_va_space = 0
         fix: Set kernel.randomize_va_space = 2.
...
43 finding(s) across 4 file(s): 9 high, 22 medium, 11 low, 1 note
```

## 为什么还要一个加固工具？

因为现有的工具审计的都是**活系统**，而没人抓的故障模式藏在**文件**里：

| | 它是什么 | 为什么不够 |
|---|---|---|
| CIS 基线 / `lynis` | 审计运行中的主机 | 必须有主机；审不了仓库、镜像或 PR |
| `sysctl --system` | 应用配置文件 | **静默**应用：最后一个文件获胜，没有人被告知 |
| Ansible 等配置管理 | 收敛到目标值 | 收敛掩盖冲突——两个 role 互相打架，谁赢看顺序 |

sysctlvet 是一个**零运行时依赖**的 Python 包，直接读配置文件本身。它懂加载顺序——
`/usr/lib/sysctl.d` 输给 `/run/sysctl.d` 输给 `/etc/sysctl.d` 输给 `/etc/sysctl.conf`，
同目录内按文件名排序——所以它能证明哪一行到达了内核，哪些行只是装饰。

它可以跑在 CI 里、刚接手的主机上、应急响应的 shell 里，以及编辑器 agent 里。

## 三步跑通

```console
# 1. 安装（没有依赖需要解析）
pip install git+https://github.com/xuange-hu/sysctlvet

# 2. 审计机器上的真实配置
sysctlvet scan /etc/sysctl.conf /etc/sysctl.d/

# 3. 问优先级引擎：这个 key 到底谁说了算
sysctlvet effective kernel.randomize_va_space /etc/sysctl.conf /etc/sysctl.d/
kernel.randomize_va_space  (load order: earlier loses, later wins)
  [dead] /usr/lib/sysctl.d/50-default.conf:3  kernel.randomize_va_space = 2
  [WINS] /etc/sysctl.conf:12  kernel.randomize_va_space = 0
```

手头没有机器？`sysctlvet demo` 跑内置语料——一台被四个人先后配置过的主机——
31 条规则全部命中。

## 检查什么

三遍扫描，31 条规则（全文见 [docs/rules.md](docs/rules.md)）：

| 扫描遍 | 规则 | 看什么 |
|---|---|---|
| `settings` | SYS101–SYS120、SYS199 | 单个生效值：ICMP 重定向、ASLR、BPF、崩溃转储、链接保护 |
| `combos` | SYS201–SYS205 | 放在一起才危险的值：KASLR 击破三件套、崩溃转储利用链 |
| `relations` | SYS301–SYS305 | 文件之间的缝隙：死配置、被回退的加固、分隔符重复、接口级覆盖 |

规则集有两个值得知道的立场：

- **只评判生效值。** 死行不会触发「设置」类结论——它触发「死行」类结论。
  只看单个文件的审计会把一台暴露的主机报成安全的。
- **缺少设置不算问题。** 与 sshd/sudoers 不同，未设置的 sysctl key 会回退到
  现代内核上合理的默认值；把「缺席」当问题会淹没真信号。（如果你想要
  「必须显式设置」的基线，提 issue，它会变成一类规则。）

## 优先级引擎

这是别的工具没有的部分：

```console
$ sysctlvet effective net/ipv4/ip_forward etc/ sys/
net.ipv4.ip_forward  (load order: earlier loses, later wins)
  [dead] etc/sysctl.d/10-network.conf:2  net/ipv4/ip_forward = 1
  [WINS] etc/sysctl.d/99-local.conf:6  net.ipv4.ip_forward = 1
```

`net/ipv4/ip_forward` 和 `net.ipv4.ip_forward` 是同一个 key——内核只认斜杠，
工具两种都收——但人看 diff 时以为是两个设置。sysctlvet 会合并它们并明说
（SYS303），因为其中一行是死的，而 diff 把这一点藏起来了。

## 证据式输出

每条结论都带 `文件`、`行号`、`字节偏移`、`长度` 和原始行。SARIF 保留同样字段，
代码扫描界面能显示片段；`--fail-on high` 就是 CI 门禁：

```console
sysctlvet scan etc/ --format sarif --fail-on high > sysctlvet.sarif
```

## MCP server

sysctlvet 为 Claude Code / Cursor / Cline 提供 6 个 MCP 工具——scan、
effective（优先级引擎）、parse、demo、rules、explain：

```console
uvx --from "git+https://github.com/xuange-hu/sysctlvet#egg=sysctlvet[mcp]" sysctlvet-mcp
```

其中 `sysctlvet_effective` 是 agent 真正想要的工具：给它 key 和文件，
它回答「哪一行赢了、谁死了」——这是所有配置评审最终都要问的问题。

## 安装说明

- Python 3.10+，零运行时依赖（mcp server 是可选 extra 且惰性导入——核心包永不触碰它）。
- 访客第一次 `git clone && pip install . && pytest` 离线可跑、只需基础依赖；
  CI 强制验证（`fresh-clone` job），并带 README 徽章数 vs pytest 收集数校验。

## 相关工具

零依赖审计器家族的一员，一个工具对准一个配置面：
[vehsec](https://github.com/xuange-hu/vehsec)（汽车安全）、
[sshdguard](https://github.com/xuange-hu/sshdguard)（sshd_config）、
[sudolint](https://github.com/xuange-hu/sudolint)（sudoers）、
[unitlint](https://github.com/xuange-hu/unitlint)（systemd unit）、
[cronlint](https://github.com/xuange-hu/cronlint)（crontab）、
[firelint](https://github.com/xuange-hu/firelint)（防火墙规则）、
[hookvet](https://github.com/xuange-hu/hookvet)（git hooks）。

## 许可证

MIT。规则刻意有立场，每一条都在 [docs/rules.md](docs/rules.md) 里给出论据——
不同意就开 issue。
