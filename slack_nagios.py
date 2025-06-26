import os
import sys
import json
import time
import logging
import threading
import warnings

from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.adapter.flask import SlackRequestHandler
from gevent.pywsgi import WSGIServer
from flask import Flask, make_response, request

# ignore slack warnings about text not being sent
warnings.filterwarnings("ignore", category=UserWarning)

# setup flask for non-slack routes

load_dotenv()
NAGIOS_URL = os.getenv("NAGIOS_URL", "https://nagios.example.com/nagios4/")
SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')
SLACK_APP_TOKEN = os.getenv('SLACK_APP_TOKEN')

# debug log if set in env
log_level = logging.DEBUG if os.getenv("DEBUG", "").lower() == "true" else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Cache for messages, needs to be writable
problems_file = 'problems.json'

# standard files placement for nagios cmd to listen
nagios_cmdfile = "/var/lib/nagios4/rw/nagios.cmd"

app = App(token=SLACK_BOT_TOKEN)
handler = SlackRequestHandler(app)

flask_app = Flask(__name__)

socket_mode_handler = SocketModeHandler(app, SLACK_APP_TOKEN)

def alert_message(data):
    state = data['state']

    # use the bootstrap palette
    # https://www.color-hex.com/color-palette/5452
    if state == "CRITICAL" or state == 'DOWN':
        color = '#d9534f'
        add_ack = True
    elif state == "OK" or state == "UP" or state == "RECOVERY":
        color = '#5cb85c'
        add_ack = False
    elif state == "WARNING":
        color = '#428bca'
        add_ack = True
    else:
        color = '#cccccc'
        add_ack = False

    if data['type'] == "ACKNOWLEDGEMENT":
        add_ack = False
        color = '#428bca'

    if data.get("acked"):
        add_ack = False
        color = "#999999"  # muted gray for acknowledged

    if 'service' in data:
        notification_message = '''
*<{}/cgi-bin/extinfo.cgi?type=2&host={}&service={}&service_id={}|Service {} notification>*
Host:\t\t\t{host}
IP:\t\t\t\t{ip}
Service:\t\t{service}
State:\t\t\t{state}
'''.format(
            NAGIOS_URL.rstrip("/"),
            data['host'],
            data['service'],
            data['service_problem_id'],
            data['type'],
            host=data['host'],
            ip=data['ip'],
            service=data['service'],
            state=data['state']
        )
        value_data = "ACKNOWLEDGE_SVC_PROBLEM;{host};{service}".format(service=data['service'], host=data['host'])
    else:
        notification_message = '''
*<{}/cgi-bin/extinfo.cgi?type=1&host={}&host_id={}|Host {} notification>*
Host:\t\t\t{host}
IP:\t\t\t\t{ip}
State:\t\t\t{state}
'''.format(
            NAGIOS_URL.rstrip("/"),
            data['host'],
            data['host_problem_id'],
            data['type'],
            host=data['host'],
            ip=data['ip'],
            state=data['state']
        )
        value_data = "ACKNOWLEDGE_HOST_PROBLEM;{host}".format(host=data['host'])

    response = [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": notification_message
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Check Output*\n{info}".format(info=data['info'])
                        }
                    },
                ],
                "fallback": notification_message
            }
        ]

    if add_ack:
        ackbutton = {
                        "type": "actions",
                        "elements": [{
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Acknowledge",
                            },
                            "value": value_data,
                            "action_id": "ack_message"
                            }
                        ]
                    }
        response[0]['blocks'].append(ackbutton)

    return response

# ack via slack
# original message will be updated via nagios with ack_message
@app.action("ack_message")
def ack_message_handler(body, ack, say, payload):
    ack()
    logging.debug("Ack message handler for: %s", json.dumps(payload, indent=2))

    # send acknowledgement to Nagios
    cmdfile = open(nagios_cmdfile, "a")
    if 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
        alertresp = "Service Problem notification for %s on %s" % (payload['value'].split(';')[1], payload['value'].split(';')[2])
        print("[%d] %s;2;1;0;%s;%s acknowledged via %s.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'], body['channel']['name'] ), file=cmdfile)
        logging.info("[%d] %s;2;1;0;%s;%s acknowledged via #%s", time.time(), payload['value'], body['user']['username'], body['user']['username'],body['channel']['name'] )
    else:
        alertresp = "Host Problem notification for %s" % payload['value'].split(';')[1]
        print("[%d] %s;2;1;0;%s;%s acknowledged via %s.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'], body['channel']['name'] ), file=cmdfile)
        logging.info("[%d] %s;2;1;0;%s;%s acknowledged via #%s", time.time(), payload['value'], body['user']['username'], body['user']['username'],body['channel']['name'] )

    # update original message color and remove button
    # find the channel and ts from stored problems
    channel = body['channel']['id']
    user = body['user']['username']
    # find the problem in problems cache to get ts
    problem_id = None
    if 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
        parts = payload['value'].split(';')
        host = parts[1]
        service = parts[2]
        for pid, info in problems.get('service', {}).items():
            if info.get('host') == host:
                problem_id = pid
                break
    else:
        parts = payload['value'].split(';')
        host = parts[1]
        for pid, info in problems.get('host', {}).items():
            if info.get('host') == host:
                problem_id = pid
                break

    if problem_id:
        ts = None
        if 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
            ts = problems['service'][problem_id]['ts']
        else:
            ts = problems['host'][problem_id]['ts']


        # Update the original message: change color and remove button by sending a new message with acked=True
        # Reconstruct data dictionary for alert_message with acked=True
        # We need to reconstruct data from stored info
        stored_info = None
        if 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
            stored_info = problems['service'][problem_id]
        else:
            stored_info = problems['host'][problem_id]

        # print our stored info
        logging.debug(f"{stored_info}")

        # Use stored_info['data'] as the base for alert_message data, update with ack info
        data = stored_info["data"].copy()
        data.update({
            "acked": True,
            "channel": channel,
            "type": "ACKNOWLEDGEMENT",
        })
        if 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
            data['service'] = service
            data['service_problem_id'] = problem_id
        else:
            data['host_problem_id'] = problem_id

        try:
            app.client.chat_update(
                channel=channel,
                ts=ts,
                attachments=alert_message(data),
                text=" "
            )
        except Exception as e:
            logging.error("Failed to update message after ack: %s", e)

# ack from Nagios
def ack_message(data):
    if 'service' in data:
        alertresp = "Service Problem notification for %s on %s" % (data['service'], data['host'])
    else:
        alertresp = "Host Problem notification for %s" % (data['host'])

    if data['type'] == 'RECOVERY' or data['type'] == 'OK' or data['type'] == 'UP':
        color = '#5cb85c'
    elif data['type'] == "ACKNOWLEDGEMENT":
        color = '#428bca'

    updated_message = [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{data['author']} acknowledged alert _\"{alertresp}\"_, {data['comment']}"
                        }
                    }
                ],
                "fallback": alertresp
            }]

    return updated_message

# Be able to send messages from Flask


try:
    with open(problems_file, 'wb') as f:
        problems = json.load( open(problems_file) )
except: 
    problems = { "service":{}, "host":{} }

@flask_app.route("/alertmsg", methods=["POST"])
def slack_events():
    data = request.get_json(force=True)
    logging.info("Received alert: type=%s service=%s host_problem_id=%s service_problem_id=%s", data.get("type"), data.get("service"), data.get("host_problem_id", "-"), data.get("service_problem_id", "-"))
    logging.debug("Full alert payload: %s", json.dumps(data, indent=2))
    is_cached = False

    if data['type'] not in ['ACKNOWLEDGEMENT', 'RECOVERY']:
        message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")
        # store message timestamp so we can handle ack's from Nagios (no callback, so we need to remember them)
        # host and service problem id can potentially overlap, so needs to be handled separately.
        if 'service' in data:
            problems['service'][data['service_problem_id']] = {
                "ts": message['ts'],
                "text": message['message']['attachments'][0]['blocks'][0]['text']['text'],
                "channel": message['channel'],
                "host": data['host'],
                "data": data
            }
        else:
            problems['host'][data['host_problem_id']] = {
                "ts": message['ts'],
                "text": message['message']['attachments'][0]['blocks'][0]['text']['text'],
                "channel": message['channel'],
                "host": data['host'],
                "data": data
            }

        # persist the alerts
        # https://stackoverflow.com/a/55109482
        with open(problems_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, ensure_ascii=False, indent=4)

    else:
        if 'service' in data:
            if data['service_problem_id'] not in problems['service']:
                # send regular ack message since we dont have the problem in our cache
                logging.warning("Could not find the error %s for %s on host %s in our cache, ignoring.", data['service_problem_id'], data['service'], data['host'])
                message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")
            else:
                is_cached = True
        else:
            # recovery for a host has problem_id set to 0, so let's iterate and see if we have it.
            if data['host_problem_id'] == "0":
                for problem_id in problems['host']:
                    if data['host'] == problems['host'][problem_id]['host']:
                        logging.info("found the host by iterating over all host in problems store: %s", data['host'])
                        is_cached = True
            # send regular ack message if we don't have it cached
            elif data['host_problem_id'] not in problems['host']:
                logging.warning("Could not find the error %s for host %s in our cache, ignoring.", data['host_problem_id'], data['host'])
                message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")
            else:
                is_cached = True

        if is_cached and data['type'] != 'RECOVERY':
            logging.debug("Cached alert: %s", json.dumps(data, indent=2))
            data['acked'] = True
            # do not send extra message for ACKNOWLEDGEMENT

        # send a separate recovery message for visibility
        if data['type'] == 'RECOVERY':
            logging.info(f"Posting separate RECOVERY message for {data.get('service', data['host'])} on *{data['host']} is now OK")
            message = app.client.chat_postMessage(
                channel=data['channel'],
                attachments=[{
                    "color": "#5cb85c",
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"✅ Recovered: *{data.get('service', data['host'])}* on *{data['host']}* is now OK"
                            }
                        }
                    ],
                    "fallback": "Recovered"
                }],
                text=" "
            )

    # print(json.dumps(problems, indent=2))
    return "ok\n"

def run_socket_handler():
    logging.info("Starting SocketModeHandler.")
    socket_mode_handler.start()

# Always start the Slack SocketModeHandler in a background thread,
# regardless of whether this file is run directly or imported (e.g. under Gunicorn).
threading.Thread(target=run_socket_handler, daemon=True).start()
