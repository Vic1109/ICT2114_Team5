# Setting up a new environment

Step-by-step setup of the Wazuh Telemetry Analyser on a fresh Ubuntu server or
cloud VM (for example Google Cloud Compute Engine with NVIDIA GPUs). For the
meaning of every setting, see [operations.md](operations.md).

## What is created automatically and what is not

| Item | Automatic? | Who does it |
|---|---|---|
| PostgreSQL server, pgvector package | No | You, step 2 |
| Database role (`DB_USER`) | No | You, step 2 |
| Database (`DB_NAME`) | Only with `DB_AUTO_CREATE=true` and a role that has `CREATEDB` | You, step 2 (recommended) |
| `vector` extension in the database | Tried at startup, but needs superuser rights, so create it yourself | You, step 2 |
| All application tables | **Yes**, on every startup (`CREATE TABLE IF NOT EXISTS`) | The app |
| User accounts and audit log (SQLite at `AUTH_DB_PATH`) | **Yes**, with the `WEB_USERNAME` account as the first admin | The app |
| Knowledge base content (CTI documents, archives) | No, it starts empty | An admin, step 8 |
| llama.cpp, the GGUF model, `.env` | No, none are in Git | You, steps 4–6 |

## 1. VM requirements

- Ubuntu 22.04 or 24.04.
- NVIDIA GPUs with roughly 36 GB of GPU memory in total for the Q8_0
  Qwen3-30B model (the lab server uses 4 × GTX 1080 Ti). Less is enough for a
  smaller quantization, and no GPU is needed if you only use Public LLM.
- A **persistent disk** for the repository, model, `.env`, auth database,
  reports and PostgreSQL data, so nothing is lost when the VM restarts.
- Port 8000 reachable only from your network or a reverse proxy, not the
  whole internet.

## 2. System packages and database

```bash
sudo apt update
sudo apt install -y git python3-venv python3-dev build-essential cmake \
  postgresql postgresql-contrib libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0
```

Install pgvector for your PostgreSQL version (check it with `psql --version`;
Ubuntu 24.04 ships 16):

```bash
sudo apt install -y postgresql-16-pgvector
```

Create the role, the database and the extensions. Use your own password and
put the same values in `.env` later:

```bash
sudo -u postgres psql <<'SQL'
CREATE ROLE soc_user LOGIN PASSWORD 'choose-a-strong-password';
CREATE DATABASE soc_rag OWNER soc_user;
\c soc_rag
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
SQL
```

`pg_trgm` is optional: without it exact-match retrieval still works, just
more slowly.

## 3. NVIDIA driver and CUDA (local model only)

Install the NVIDIA driver and CUDA toolkit for your GPUs (on Google Cloud, use
a GPU image or Google's driver installer), then confirm:

```bash
nvidia-smi
```

## 4. Get the code

```bash
git clone https://github.com/Vic1109/ICT2114_Team5.git
cd ICT2114_Team5
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r Linux_LLM/config/requirements.txt
```

## 5. llama.cpp and the model (local model only)

Build llama.cpp with CUDA outside the repository:

```bash
git clone https://github.com/ggml-org/llama.cpp ~/llama.cpp
cmake -S ~/llama.cpp -B ~/llama.cpp/build -DGGML_CUDA=ON
cmake --build ~/llama.cpp/build --config Release -j
```

This produces `~/llama.cpp/build/bin/llama-cli` and `llama-server`. Keep them
side by side; the app starts `llama-server` itself.

Copy the **same GGUF file** the current server uses (Qwen3-30B-A3B Instruct,
Q8_0) to the new VM, for example into `~/models/`. Using the identical file
keeps reports comparable between environments. Model files are too large for
Git and are not in the repository.

## 6. Configure `.env`

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set at least:

| Setting | Value |
|---|---|
| `LLM_MODEL_PATH` | Full path to the GGUF file |
| `LLM_BINARY_PATH` | Full path to `llama-cli` |
| `WEB_USERNAME`, `WEB_PASSWORD` | First admin account (password of at least 12 characters) |
| `WEB_SESSION_SECRET` | Output of `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`. Keep it; changing it logs everyone out and resets MFA. |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD` | The values from step 2 |
| `AUTH_DB_PATH` | A path on the persistent disk, e.g. `/home/<user>/soc-state/users.sqlite3` |
| `REPORTS_DIR`, `UPLOADS_DIR` | Paths on the persistent disk |
| `ANTHROPIC_API_KEY` | Only if Public LLM will be used |
| `SSH_HOST`, `SSH_USERNAME`, `SSH_PASSWORD` | Only for live Wazuh alerts; leave all three empty for upload-only |
| `LLM_TENSOR_SPLIT`, `LLM_GPU_LAYERS` | Match the new VM's GPUs |

Never commit `.env`.

## 7. Check, then start

Run the preflight check. It reports missing paths, database problems and
missing pgvector before you start the app:

```bash
python3 Linux_LLM/config/runtime_preflight.py
```

To start the app automatically at boot and restart it after a crash, create
`/etc/systemd/system/soc-rag.service` (adjust user and paths):

```ini
[Unit]
Description=SOC Threat Analyser
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
User=<user>
WorkingDirectory=/home/<user>/ICT2114_Team5
Environment=ENV_FILE=/home/<user>/ICT2114_Team5/.env
ExecStart=/home/<user>/ICT2114_Team5/.venv/bin/python Linux_LLM/config/main.py
Restart=on-failure
RestartSec=10
StartLimitBurst=5
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now postgresql soc-rag
journalctl -u soc-rag -f
```

On the first start the app creates its tables and the first admin account.

## 8. First sign-in and knowledge base

1. Open `http://<vm-address>:8000` (or your reverse proxy address) and sign
   in with `WEB_USERNAME` / `WEB_PASSWORD`.
2. Scan the QR code with Microsoft Authenticator to set up MFA.
3. Go to **Knowledge base** and upload your CTI documents and/or add Wazuh
   archive data. The new database is empty, so analyses have no CTI context
   until this build finishes.
4. Create analyst accounts on the **Accounts** page, or leave
   `WEB_ALLOW_REGISTRATION=true` for self sign-up.

To reuse an existing knowledge base instead of rebuilding it, back up the old
server's database and restore it on the new one, as described in
[Database backup and recovery](operations.md#database-backup-and-recovery).
Copy the old `AUTH_DB_PATH` file and keep the same `WEB_SESSION_SECRET` to
keep the existing accounts and MFA enrolments.

## 9. Updating later

The code stays on the disk across reboots, so you only pull when `main` has
new changes:

```bash
cd ~/ICT2114_Team5
git pull origin main
source .venv/bin/activate
python -m pip install -r Linux_LLM/config/requirements.txt
sudo systemctl restart soc-rag
```

The pip step only matters when `requirements.txt` changed, but it is safe to
run every time. Tables for new features are created automatically on restart.
