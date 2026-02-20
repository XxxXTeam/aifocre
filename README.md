# AiForce 批量注册工具

高性能的 AiForce API 账号批量注册工具，支持并发注册、自动邀请码管理、模型启用，内置 Turnstile 验证码解决方案。

## 功能特性

- **高速并发注册** — 信号量控制注册并发，验证码预解池异步供给
- **邀请码自循环** — 注册后自动获取邀请码，供后续账号使用，uses 达上限自动轮换
- **模型批量启用** — 注册完成后自动启用 25 个 AI 模型
- **多 Solver 实例** — 支持逗号分隔多个 Turnstile Solver 地址，线性扩展吞吐
- **Solver 联动启动** — 加 `-browsers 8` 即可自动启动/停止 Turnstile Solver，无需手动管理
- **零外部依赖** — Go 纯标准库实现，单文件编译，无需 CGO

## 前置条件

- **Go** 1.25+
- **uv** — Python 包管理器（仅使用联动启动时需要）
  ```bash
  # 安装 uv (https://docs.astral.sh/uv/)
  curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows
  ```

## 快速开始

```bash
go build -o aifocre.exe .
./aifocre -count 50 -concurrent 4
```

程序启动时会自动：
1. **探测 Solver** — 尝试连接 `http://127.0.0.1:5072`
2. **自动唤醒** — 连不上时自动查找 `solver/` 目录，安装依赖（uv 优先，fallback pip），安装浏览器，启动 Solver
3. **自动清理** — 程序结束或 Ctrl+C 时自动停止 Solver 子进程

> 首次运行时会自动安装 Python 依赖和 Chromium 浏览器，耗时较长，后续启动秒开。

### 手动启动 Solver（可选）

如果希望独立管理 Solver 进程：

```bash
cd solver
uv run python api_solver.py --thread 8 --port 5072
```

程序检测到 Solver 已在运行时会直接使用，不会重复启动。

### 准备邀请码（可选）

在项目目录下创建 `code.json`，格式如下：

```json
[
  {"code": "your_referral_code", "uses": 0}
]
```

> 如果没有邀请码，程序也能正常运行，注册后会自动获取并保存。

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-count` | `1` | 注册账号数量 |
| `-concurrent` | `1` | 注册并发数（同时进行的注册流程） |
| `-workers` | `自动` | 验证码预解并发数（默认=browsers 或 concurrent*2） |
| `-browsers` | `4` | 自动启动 Solver 时的浏览器线程数 |
| `-solver` | `http://127.0.0.1:5072` | Turnstile Solver 地址，多个用逗号分隔 |
| `-data` | `.` | 数据文件保存目录 |

## 使用示例

```bash
# 最简用法：自动探测/启动 Solver
./aifocre -count 50 -concurrent 4

# 指定 Solver 浏览器数量
./aifocre -count 50 -concurrent 4 -browsers 8

# 已有外部 Solver 运行，直接使用
./aifocre -count 50 -concurrent 4 -workers 8

# 多 solver 实例
./aifocre -count 100 -concurrent 6 -workers 16 \
  -solver "http://127.0.0.1:5072,http://127.0.0.1:5073"

# 指定数据目录
./aifocre -count 20 -concurrent 3 -data ./output
```

## 输出文件

| 文件 | 内容 |
|------|------|
| `api_keys.txt` | API Key，每行一个 |
| `accounts.txt` | 完整账号信息，格式：`用户名\|密码\|API Key` |
| `code.json` | 邀请码池（自动维护 uses 计数） |

## 架构说明

```
主循环 (count 个任务)
  │
  ├── 信号量 sem (concurrent 个槽位)
  │     │
  │     └── doSignup: captchaPool.get() + signup()
  │           │
  │           ├── 成功 → 释放 sem → 下一个立即开始
  │           │         └── 后台异步 doPostSignup
  │           │               ├── getUserInfo → 写 api_keys.txt / accounts.txt
  │           │               ├── getReferralCode → 存入邀请码池
  │           │               └── enableModels (25个模型并发启用)
  │           │
  │           └── 失败 → 释放 sem → 记录错误
  │
  └── CaptchaPool (workers 个协程)
        └── worker: solveCaptcha() → tokens channel (buffer=workers*3)
```

## Solver 目录

`solver/` 包含 Turnstile 验证码解决服务，使用 [uv](https://docs.astral.sh/uv/) 管理 Python 依赖：

```
solver/
├── pyproject.toml      # uv 项目配置和依赖声明
├── api_solver.py       # HTTP API 服务主程序
├── browser_configs.py  # 浏览器指纹配置
├── db_results.py       # 任务结果内存存储
└── requirements.txt    # pip 兼容依赖（备用）
```

```bash
# 手动启动 Solver（uv 自动管理虚拟环境和依赖）
cd solver
uv run python api_solver.py --thread 8 --port 5072
```

> 使用 `-browsers` 联动模式时，Go 会自动调用 `uv run --project solver/ python solver/api_solver.py`，
> 首次运行 uv 会自动创建虚拟环境并安装依赖，无需手动操作。

## 构建

### 本地构建

```bash
go build -o aifocre.exe .
```

### 交叉编译

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o aifocre .

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o aifocre .
```

### GitHub Actions

推送代码或创建 tag 时自动构建多平台二进制文件，详见 `.github/workflows/build.yml`。

## License

MIT
