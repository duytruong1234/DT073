# Dockerfile tái lập môi trường thực nghiệm Đề tài DT073
# Dữ liệu: CVEfixes v1.0.8 (DOI: 10.5281/zenodo.4476563, CC BY 4.0)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=42 \
    PIP_NO_CACHE_DIR=1

# Cài đặt git và các gói hệ thống tối thiểu (chỉ dùng để đọc lịch sử git khi xác thực commit)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Tạo người dùng không đặc quyền (non-root) theo đúng ràng buộc Threat Model
RUN useradd -m -u 1000 dt073user
WORKDIR /workspace/DT073

COPY requirements-lock.txt requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements-lock.txt

COPY --chown=dt073user:dt073user . .
USER dt073user

# Mặc định chạy bộ kiểm thử 74 test và kịch bản demo
CMD ["pytest", "-q", "tests/"]
