# AiForce 批量注册工具

高性能的 AiForce API 账号批量注册工具，支持并发注册、自动邀请码管理、模型启用，内置 Turnstile 验证码解决方案。

## 功能特性

- **高速并发注册** — 信号量控制注册并发，验证码预解池异步供给
- **邀请码自循环** — 注册后自动获取邀请码，供后续账号使用，uses 达上限自动轮换
- **模型批量启用** — 注册完成后自动启用 25 个 AI 模型
- **多 Solver 实例** — 支持逗号分隔多个 Turnstile Solver 地址，线性扩展吞吐
- **零外部依赖** — Go 纯标准库实现，单文件编译，无需 CGO

## 快速开始

### 1. 启动 Turnstile Solver

```bash
cd solver
pip install -r requirements.txt
python api_solver.py --browsers 8 --port 5072
```

### 2. 准备邀请码（可选）

在项目目录下创建 `code.json`，格式如下：

```json
[
  {"code": "your_referral_code", "uses": 0}
]
```

> 如果没有邀请码，程序也能正常运行，注册后会自动获取并保存。

### 3. 编译运行

```bash
go build -o aifocre.exe .
./aifocre -count 50 -concurrent 4
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-count` | `1` | 注册账号数量 |
| `-concurrent` | `1` | 注册并发数（同时进行的注册流程） |
| `-workers` | `concurrent*2` | 验证码预解并发数（应匹配 Solver 的 browser 数） |
| `-solver` | `http://127.0.0.1:5072` | Turnstile Solver 地址，多个用逗号分隔 |
| `-data` | `.` | 数据文件保存目录 |

## 使用示例

```bash
# 基本用法：注册 10 个账号，3 路并发
go run . -count 10 -concurrent 3

# 指定 workers 匹配 solver 的 8 个浏览器
go run . -count 50 -concurrent 4 -workers 8

# 多 solver 实例，吞吐翻倍
go run . -count 100 -concurrent 6 -workers 16 \
  -solver "http://127.0.0.1:5072,http://127.0.0.1:5073"

# 指定数据目录
go run . -count 20 -concurrent 3 -data ./output
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

`solver/` 包含 Turnstile 验证码解决服务：

- `api_solver.py` — HTTP API 服务主程序
- `browser_configs.py` — 浏览器指纹配置
- `db_results.py` — 任务结果内存存储
- `requirements.txt` — Python 依赖

```bash
# 启动参数示例
python solver/api_solver.py --browsers 8 --port 5072
```

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
