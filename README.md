# Nagios - Slack notifier

## Installation

Checkout this repo into nagios dir:

`git clone https://github.com/joltcan/slack_nagios_notifier.git /var/lib/nagios/slack_notifier/``

Create venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Add tokens to .env file:

```bash
SLACK_BOT_TOKEN=xoxb-
SLACK_APP_TOKEN=xapp-
```

# Run in shell

Activate env as user nagios:

```bash
su nagios
cd ~/slack_notifier
source .venv/bin/activate
.venv/bin/gunicorn --bind 127.0.0.1:5000 slack_nagios:flask_app
```

# Run as Service

To run the notifier as a systemd service (runs as user `nagios`, but managed by root):

```bash
systemctl edit --full --force slack_notifier.service
```

Paste the following:

```ini
[Unit]
Description=Slack Nagios Notifier
After=network.target

[Service]
Type=simple
User=nagios
WorkingDirectory=/var/lib/nagios/slack_notifier
ExecStart=/var/lib/nagios/slack_notifier/.venv/bin/gunicorn --workers 1 --bind 127.0.0.1:5000 slack_nagios:flask_app
Restart=on-failure
EnvironmentFile=/var/lib/nagios/slack_notifier/.env

[Install]
WantedBy=multi-user.target
```

Then enable and start the service (run these as root):

```bash
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable --now slack_notifier.service
```

Check logs with:

```bash
journalctl -u slack_notifier.service -f
```

# Debug

Add `DEBUG=True` to .env file.
