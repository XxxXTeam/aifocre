##
## 阶段 1：编译 Go 二进制
##
FROM golang:1.24-bookworm AS builder

WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /aifocre .

##
## 阶段 2：运行时环境（Python + uv + solver）
##
FROM python:3.12-slim-bookworm

## 安装 uv（极速 Python 包管理器）
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

## 复制 Go 二进制
COPY --from=builder /aifocre /usr/local/bin/aifocre

## 复制 solver 源码
WORKDIR /app
COPY solver/ ./solver/

## 安装 Python 依赖 + 浏览器
RUN uv sync --project solver/ \
    && uv run --project solver/ patchright install chromium --with-deps \
    && uv run --project solver/ python -m camoufox fetch

## 数据持久化目录
VOLUME /app/data

ENV PYTHONIOENCODING=utf-8

ENTRYPOINT ["aifocre"]
CMD ["-count", "1", "-concurrent", "1", "-data", "/app/data"]
