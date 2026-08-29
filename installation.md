\## Installation



\### Prerequisites



| Tool | Why | Version |

|------|-----|---------|

| \*\*Node.js\*\* or \*\*bun\*\* | Runs the Next.js web app | 18+ / latest |

| \*\*Python\*\* | Runs `scanner.py` | 3.10+ |

| \*\*Chromium\*\* | Playwright's headless browser | Latest |



\### Kali Linux



```bash

\# 1. Unzip

unzip webrecon-webapp.zip

cd webrecon-webapp



\# 2. Install Node.js (if not already installed)

curl -fsSL https://deb.nodesource.com/setup\_20.x | sudo -E bash -

sudo apt-get install -y nodejs



\# 3. Install bun (recommended — faster than npm)

curl -fsSL https://bun.sh/install | bash

source \~/.bashrc



\# 4. Install Node.js dependencies

bun install



\# 5. Install Python dependencies into a venv named .venv

\#    (The dev server auto-detects .venv/bin/python3 — no manual PATH setup needed.)

sudo apt-get install -y python3-pip python3-venv

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt   # installs playwright + cryptography + python-dotenv



\# 6. Install Chromium for Playwright

playwright install chromium

sudo playwright install-deps chromium   # installs OS libs Chromium needs



\# 7. Set up the database

cp .env.example .env          # creates .env with DATABASE\_URL=file:../db/webrecon.db

bun run db:push               # creates db/webrecon.db + tables (runs prisma db push)



\# 8. Start the web app

bun run dev



\# 9. Open http://localhost:3000

```



> \*\*No venv? No problem.\*\* If you skip step 5 and just install playwright

> system-wide (`pip install playwright`), the dev server's

> `findPythonWithPlaywright()` helper will discover it automatically. It

> probes `python3`, `python`, `<project>/.venv/bin/python3`,

> `$HOME/.venv/bin/python3`, and several other common locations.

>

> \*\*Airgapped install?\*\* Pre-install playwright + Chromium on a machine

> with internet, then copy the entire `.venv/` directory + the

> `\~/.cache/ms-playwright/` directory to the airgapped machine.



\### Windows



```powershell

\# 1. Unzip

Expand-Archive webrecon-webapp.zip

cd webrecon-webapp



\# 2. Install Node.js from https://nodejs.org (LTS)

winget install OpenJS.NodeJS.LTS



\# 3. Install Python from https://python.org (3.10+)

winget install Python.Python.3.12



\# 4. Install Node.js dependencies

npm install



\# 5. Install Python dependencies into a venv named .venv

python -m venv .venv

.venv\\Scripts\\activate

pip install -r requirements.txt



\# 6. Install Chromium

playwright install chromium



\# 7. Set up the database

copy .env.example .env

npm run db:push



\# 8. Start the web app

npm run dev



\# 9. Open http://localhost:3000

```



> \*\*Windows DATABASE\_URL\*\*: The `.env.example` file uses a RELATIVE path

> (`file:../db/webrecon.db`) so it works on Windows without modification.

> Do NOT change it to an absolute Unix path like `file:/home/.../db/custom.db`

> — on Windows the leading `/` resolves to the current drive root (e.g.

> `Z:\\home\\...`) and Prisma will throw a confusing `Z:/` error.

>

> \*\*Why `../db/` and not `./db/`?\*\* Prisma resolves relative DB paths from

> the directory containing `prisma/schema.prisma` (i.e. the `prisma/`

> folder), NOT from `process.cwd()`. So `file:./db/webrecon.db` would

> create `prisma/db/webrecon.db` — which is NOT where the app expects it.

> Using `file:../db/webrecon.db` puts the DB at `<project-root>/db/webrecon.db`.



\### Optional: Manual Login Service (CAPTCHA / 2FA / SSO)



The "Launch Browser to Login" feature opens a real Chromium window so you

can log in manually (handles CAPTCHA, 2FA, SSO, non-standard flows). It

requires a separate mini-service running on port 3001:



```bash

\# In a separate terminal:

cd mini-services/manual-login-service

bun install

bun run dev

```



You can now use "Launch Browser to Login" from either:

\- \*\*New Scan form\*\* — log in BEFORE the scan starts (the captured session

&#x20; is passed to the scanner via `--load-state`)

\- \*\*Live View\*\* (when a scan pauses due to session expiry) — log in to

&#x20; refresh the session, then click "Resume Scan"



\### Auto-Install Playwright (Optional)



If you don't want to set up a venv manually, you can let the dev server

auto-install playwright on first scan. Set this in your `.env`:



```

WEBRECON\_AUTO\_INSTALL\_PLAYWRIGHT=1

```



When enabled, the scanner-runner will run `pip install playwright \&\&

playwright install chromium` on the first scan if no interpreter has it.

Requires internet access on first run. Disabled by default for airgapped

use.



\---



