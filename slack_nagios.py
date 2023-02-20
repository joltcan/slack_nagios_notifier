from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_bolt.adapter.flask import SlackRequestHandler

# ignore slack warnings about text not being sent
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

# use gevent as webserver in production
from gevent.pywsgi import WSGIServer

# setup flask for non-slack routes
from flask import Flask, make_response, request

import time
import json
import os

SLACK_BOT_TOKEN = os.environ['SLACK_BOT_TOKEN']
SLACK_APP_TOKEN = os.environ['SLACK_APP_TOKEN']

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
    elif state == "WARNING" or state == 'ACKNOWLEDGEMENT':
        color = '#428bca'
        add_ack = True
    else:
        color = '#cccccc'
        add_ack = False

    if 'service' in data:
        notification_message = '''
*<https://nagios.int.impactct.co/nagios4/|Service {type} notification>*
Host:\t\t\t{host}
IP:\t\t\t\t{ip}
Service:\t\t{service}
State:\t\t\t{state}
'''.format(type=data['type'], host=data['host'], ip=data['ip'], service=data['service'], state=data['state'])
        value_data = "ACKNOWLEDGE_SVC_PROBLEM;{service};{host}".format(service=data['service_problem_id'], host=data['host'])
    else:
        notification_message = '''
*<https://nagios.int.impactct.co/nagios4/|Host {type} notification>*
Host:\t\t\t{host}
IP:\t\t\t\t{ip}
State:\t\t\t{state}
'''.format(type=data['type'], host=data['host'], ip=data['ip'], state=data['state'])
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
                            "text": "*Additional info*\n{info}".format(info=data['info'])
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

@app.action("ack_message")
def ack_message_handler(body, ack, say, payload):
    ack()

    # send acknowledgement to Nagios
    cmdfile = open(nagios_cmdfile, "a")
    if 'ACKNOWLEDGE_HOST_PROBLEM' in payload['value']:
        alertresp = "Host Problem notification for %s" % payload['value'].split(';')[1]
        print("[%d] %s;2;1;0;%s;%s acknowledged via nagios-slack.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'] ), file=cmdfile)
        print("[%d] %s;2;1;0;%s;%s acknowledged via nagios-slack.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'] ))
    elif 'ACKNOWLEDGE_SVC_PROBLEM' in payload['value']:
        alertresp = "Service Problem notification for %s on %s" % (payload['value'].split(';')[1], payload['value'].split(';')[2])
        print("[%d] %s;2;1;0;%s;%s acknowledged via nagios-slack.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'] ), file=cmdfile)
        print("[%d] %s;2;1;0;%s;%s acknowledged via nagios-slack.\n" % (time.time(), payload['value'], body['user']['username'], body['user']['username'] ))

# ack from Nagios
def ack_message(data):
    if 'service' in data:
        if data['service_problem_id'] in problems['service']:
            alertresp = "Service Problem notification for %s on %s" % (data['service'], data['host'])
            old_message_ts = problems['service'][data['service_problem_id']]['ts']
            old_message = problems['service'][data['service_problem_id']]['text']
            channel = problems['service'][data['service_problem_id']]['channel']
            # print("Acked %s for %s on %s from nagios" % (data['service_problem_id'], data['service'], data['host']) )
            del problems['service'][data['service_problem_id']]
    else:
        if data['host_problem_id'] in problems['host']:
            alertresp = "Host Problem notification for %s" % (data['host'])
            old_message_ts = problems['host'][data['host_problem_id']]['ts']
            old_message = problems['host'][data['host_problem_id']]['text']
            channel = problems['host'][data['host_problem_id']]['channel']
            # print("Acked %s on %s from nagios" % (data['host_problem_id'], data['host']) )
            del problems['host'][data['host_problem_id']]

    updated_message = [
            {
                "color": "#d9534f",
                "blocks": [
                    {
                        "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": old_message
                                }
                    },
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

    # https://api.slack.com/methods/chat.update
    app.client.chat_update(channel=channel, attachments=updated_message, ts=old_message_ts)

from slack_bolt.context.say import Say
problems = { "service":{}, "host":{} }

@flask_app.route("/alertmsg", methods=["POST"])
def slack_events():
    data = request.get_json(force=True)
    print(json.dumps(data, indent=2))
    if data['type'] != 'ACKNOWLEDGEMENT':
        message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")
        # store message timestamp so we can handle ack's from Nagios (no callback, so we need to remember them)
        # host and service problem id can potentially overlap, so needs to be handled separately.
        if 'service' in data:
            problems['service'][data['service_problem_id']] = {"ts": message['ts'], "text": message['message']['attachments'][0]['blocks'][0]['text']['text'], "channel": message['channel']}
        else:
            problems['host'][data['host_problem_id']] = {"ts": message['ts'], "text": message['message']['attachments'][0]['blocks'][0]['text']['text'], "channel": message['channel']}
    if data['type'] == 'ACKNOWLEDGEMENT':
        if 'service' in data:
            if data['service_problem_id'] in problems['service']:
                message = app.client.chat_postMessage(channel=data['channel'], attachments=ack_message(data), text=" ")
            else:
                # send regular ack message if we don't have it cached
                print("Could not find the error %s for %s on host %s in our cache, ignoring." % (data['service_problem_id'], data['service'], data['host']))
                message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")
        else:
            if data['host_problem_id'] in problems['host']:
                message = app.client.chat_postMessage(channel=data['channel'], attachments=ack_message(data), text=" ")
            else:
                # send regular ack message if we don't have it cached
                print("Could not find the error %s for host %s in our cache, ignoring." % (data['host_problem_id'], data['host']))
                message = app.client.chat_postMessage(channel=data['channel'], attachments=alert_message(data), text=" ")

    # print(json.dumps(problems, indent=2))
    return "ok\n"

if __name__ == "__main__":
    socket_mode_handler.connect()  # does not block the current thread
    # Debug/Development
    if 'DEBUG' in os.environ:
        flask_app.run(port=5000, debug=True)
    else:
        print("Starting webserver.")
        http_server = WSGIServer(('', 5000), flask_app)
        http_server.serve_forever()