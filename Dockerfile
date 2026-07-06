FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# 非rootで実行 (最小権限)。rootfs 全体のスキャン等 root が必要な場合は
# `docker run --user root` で明示的に上書きする
RUN useradd --system --create-home --shell /usr/sbin/nologin hardshell
USER hardshell

ENTRYPOINT ["hardshell"]
CMD ["scan"]
