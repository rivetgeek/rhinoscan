FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    docker.io \
    git \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# AWS CLI v2 — boto3 has no `login` (web sign-in) credential provider, so the
# scanner shells out to `aws configure export-credentials` to reuse the
# operator's `aws login` session (mounted via ~/.aws). See aws_profiles.py.
RUN ARCH="$(uname -m)" \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/db /data/scans /data/reports

# No --reload: source is baked into the image so there is nothing to watch,
# and the reload supervisor keeps the socket open when the worker dies —
# requests then hang instead of the container exiting for Docker to restart.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
