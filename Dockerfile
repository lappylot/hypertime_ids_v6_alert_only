# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ---- system deps (build liboqs) ----
RUN apt-get update && apt-get install -y --no-install-recommends \
      git cmake ninja-build build-essential pkg-config ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# ---- build & install liboqs (shared) ----
RUN git clone --branch "0.14.0" --depth=1 --recurse-submodules \
      https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
  && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
       -DCMAKE_INSTALL_PREFIX=/usr/local \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_USE_OPENSSL=OFF \
       -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
       -G Ninja \
  && cmake --build /tmp/liboqs/build --parallel \
  && cmake --install /tmp/liboqs/build \
  && rm -rf /tmp/liboqs
RUN printf "/usr/local/lib\n" > /etc/ld.so.conf.d/usr-local-lib.conf && ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}

# ---- app deps ----
WORKDIR /app
# core Python deps
RUN pip install --no-cache-dir psutil httpx cryptography bleach jsonschema
# oqs Python wrapper (after liboqs is present)
RUN pip install --no-cache-dir "git+https://github.com/open-quantum-safe/liboqs-python@0.12.0"

# ---- unprivileged user ----
RUN groupadd -g 10001 app && useradd -r -u 10001 -g app -m -d /home/appuser appuser
USER appuser:app

# ---- app ----
COPY --chown=appuser:app hypertime_ids_v6_alert_only.py /app/

# ---- run ----
CMD ["python", "-u", "/app/hypertime_ids_v6_alert_only.py"]
