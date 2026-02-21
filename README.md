# AiForce 批量注册工具

高性能的 AiForce API 账号批量注册工具，支持并发注册、自动邀请码管理、模型启用，内置 Turnstile 验证码解决方案。

## 功能特性

- **高速并发注册** — 信号量控制注册并发，验证码预解池异步供给
- **邀请码自循环** — 注册后自动获取邀请码，供后续账号使用，uses 达上限自动轮换
- **模型批量启用** — 注册完成后自动启用 25+ 个 AI 模型
- **多 Solver 实例** — 支持逗号分隔多个 Turnstile Solver 地址，线性扩展吞吐
- **Solver 自动管理** — 自动探测/启动/停止 Turnstile Solver，无需手动管理
- **零外部依赖** — Go 纯标准库实现，单文件编译，无需 CGO

## 快速开始

### 方式一：下载 Release（推荐）

从 [Releases](https://github.com/XxxXTeam/aifocre/releases) 下载对应平台的压缩包，包含二进制和 solver：

```bash
# Linux / macOS
tar xzf aifocre-linux-amd64.tar.gz
cd aifocre-linux-amd64
./aifocre -count 50 -concurrent 4

# Windows
# 解压 aifocre-windows-amd64.zip
aifocre.exe -count 50 -concurrent 4
```

### 方式二：Docker 一键启动

```bash
docker run --rm -v $(pwd)/data:/app/data \
  ghcr.io/xxxteam/aifocre:latest \
  -count 50 -concurrent 4
```

或使用 `docker-compose.yml`：

```yaml
services:
  aifocre:
    image: ghcr.io/xxxteam/aifocre:latest
    volumes:
      - ./data:/app/data
    command: ["-count", "50", "-concurrent", "4"]
```

```bash
docker compose up
```

### 方式三：源码构建

```bash
git clone https://github.com/XxxXTeam/aifocre.git
cd aifocre
go build -o aifocre .
./aifocre -count 50 -concurrent 4
```

## 前置条件

使用 Release 或 Docker 方式无需额外安装。源码构建需要：

- **Go** 1.24+
- **uv** 或 **pip** — Python 包管理器（自动启动 Solver 时需要）
  ```bash
  # 安装 uv (https://docs.astral.sh/uv/)
  curl -LsSf https://astral.sh/uv/install.sh | sh   # Linux/macOS
  powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"  # Windows
  ```

## Solver 自动管理

程序启动时会自动：
1. **探测 Solver** — 尝试连接 `http://127.0.0.1:5072`
2. **自动唤醒** — 连不上时自动查找 `solver/` 目录，静默安装依赖和浏览器，启动 Solver
3. **自动清理** — 程序结束或 Ctrl+C 时自动停止 Solver 及其所有子进程

> 首次运行时会自动安装 Python 依赖和浏览器，耗时较长，后续启动秒开。

### 手动启动 Solver（可选）

```bash
cd solver
uv run python api_solver.py --thread 8 --port 5072
```

程序检测到 Solver 已在运行时会直接使用，不会重复启动。

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-count` | `1` | 注册账号数量 |
| `-concurrent` | `1` | 注册并发数（同时进行的注册流程） |
| `-workers` | `自动` | 验证码预解并发数（默认=browsers 或 concurrent×2） |
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
  │           │               └── enableModels (25+ 模型并发启用)
  │           │
  │           └── 失败 → 释放 sem → 记录错误
  │
  └── CaptchaPool (workers 个协程)
        └── worker: solveCaptcha() → tokens channel (buffer=workers×3)
```

## Solver 目录

`solver/` 包含 Turnstile 验证码解决服务：

```
solver/
├── pyproject.toml      # Python 项目配置和依赖声明
├── api_solver.py       # HTTP API 服务主程序
├── browser_configs.py  # 浏览器指纹配置
├── db_results.py       # 任务结果内存存储
└── requirements.txt    # pip 兼容依赖（备用）
```

## 构建

### 本地构建

```bash
go build -o aifocre .
```

### 交叉编译

```bash
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o aifocre .
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o aifocre .
```

### Docker 镜像

```bash
docker build -t aifocre .
docker run --rm -v $(pwd)/data:/app/data aifocre -count 50 -concurrent 4
```

### GitHub Actions

- **CI** — 每次 push/PR 自动编译检查
- **Release** — 推送 `v*` tag 时自动构建 6 平台二进制压缩包 + Docker 镜像，发布到 GitHub Releases 和 GHCR

```bash
git tag v1.0.0
git push origin v1.0.0
```

## License

[GPL-3.0](LICENSE)
