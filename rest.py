#! /usr/bin/python3

import argparse
import base64
import datetime
import hashlib
import os
import re
import time
import threading
from xml.etree import ElementTree

import requests
from zeep.wsse import utils


parser = argparse.ArgumentParser()
parser.add_argument("--env",      type=str,  default="local")
parser.add_argument("--username", type=str,  default="")
parser.add_argument("--password", type=str,  default="")
parser.add_argument("--batch",    action="store_true")
parser.add_argument("--file",     type=str,  required=True)
parser.add_argument("--threads",  type=int,  default=1)
args = parser.parse_args()

re_status = re.compile("responseCode=\"(.*)\"\s", re.DOTALL | re.IGNORECASE)
re_errors = re.compile("ErrorMessage message=\"(.*)\"/>", re.DOTALL | re.IGNORECASE)
re_body   = re.compile("<soap-env:body>(.*)</soap-env:body>", re.DOTALL | re.IGNORECASE)
endpoint  = "trs/TravelReservationSyncEndpointBinding?wsdl"
env       = {
    "local": {
        "host"    : "http://localhost:8888",
        "username": "test1",
        "password": "testpassword1",
    },
    "dev"  : {
        "host": "http://api-soap-dev.flyrlabs.com",
        "username": "test1",
        "password": "testpassword1",
    },
    "stage": {
        "host": "http://api-soap-staging.flyrlabs.com",
        "username": "test1",
        "password": "testpassword1",
    }
}.get(args.env, None)

host     = env.get("host", "")
username = env.get("username") if not args.username else args.username
password = env.get("password") if not args.password else args.password

print("Arguments used    : {}".format(args))
print("Env               : {}".format(env))
print("Endpoint          : {}/{}".format(host, endpoint))
print("Username/password : {} {}".format(username, password))
print("======================================================")


class UsernameToken(object):
    """ Simplified class taken from zeep """
    username_token_profile_ns = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0'
    soap_message_secutity_ns  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0'

    utc = datetime.timezone(-datetime.timedelta(hours=0))

    def __init__(self, username, password=None):
        self.username = username
        self.password = password

    def apply(self):
        security = utils.WSSE.Security()

        # The token placeholder might already exists since it is specified in the WSDL.
        token = security.find('{%s}UsernameToken' % utils.ns.WSSE)
        token = utils.WSSE.UsernameToken()
        security.append(token)

        # Create the sub elements of the UsernameToken element
        elements = [utils.WSSE.Username(self.username)]
        elements.extend(self._create_password_digest())

        token.extend(elements)
        return ElementTree.tostring(security).decode("ascii")

    def _create_password_digest(self):
        nonce = os.urandom(16)
        timestamp = datetime.datetime.utcnow().replace(tzinfo=self.utc, microsecond=0).isoformat()

        # digest = Base64 ( SHA-1 ( nonce + created + password ) )
        digest = base64.b64encode(
            hashlib.sha1(
                nonce + timestamp.encode('utf-8') +
                self.password.encode('utf-8')
            ).digest()
        ).decode('ascii')
        return [
            utils.WSSE.Password(
                digest,
                Type='%s#PasswordDigest' % self.username_token_profile_ns
            ),
            utils.WSSE.Nonce(
                base64.b64encode(nonce).decode('utf-8'),
                EncodingType='%s#Base64Binary' % self.soap_message_secutity_ns
            ),
            utils.WSU.Created(timestamp)
        ]


security = UsernameToken(username=username, password=password)
url      = "{host}/{endpoint}".format(host=host, endpoint=endpoint)
headers  = {"content-type": "application/soap+xml"}
envelope = """
<?xml version="1.0"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope">
  <soap-env:Header>
    {security}
    <ns:TravelReservationHeader xmlns:ns="http://schema.carlsonwagonlit.com/TravelReservationTransaction" xmlns:ns0="http://www.w3.org/2003/05/soap-envelope" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" priority="4" transactionId="46:e1fcf349-7782-4fdd-99c7-1d8016b0dad6"/>
  </soap-env:Header>
  <soap-env:Body>
    {body}
  </soap-env:Body>
</soap-env:Envelope>
"""


def prepare_and_send(reader, single_file=False):
    for index, line in reader:

        matches = re_body.findall(line)
        if len(matches) != 1:
            print("{:>6d}: Invalid number of <soap-env:body> sections.  Expected 1 found {:d}".format(index, len(matches)))
            continue

        data = "".join(envelope.format(**{
            "security": security.apply(),
            "body"    : matches[0],
        }).split("\n"))

        tic      = time.time()
        response = requests.post(url, data=data, headers=headers)
        toc      = time.time()

        status  = re_status.findall(response.content.decode("ascii"))
        message = re_errors.findall(response.content.decode("ascii"))
        print("{:>6d}: got {} in {:>4.2f}s. Message: {}".format(index, status, (toc - tic), message))

        if single_file:
            return


def mutex(func):
    def wrapper(self, *args, **kwargs):
        self.lock.acquire()
        try:
            data = func(self, *args, **kwargs)
        except StopIteration as e:
            raise StopIteration
        else:
            return data
        finally:
            self.lock.release()
    return wrapper


class Reader(object):

    def __init__(self, filename):
        self.file = open(filename, "r")
        self.lock = threading.Lock()
        self.row  = 0
        self.open = True

    def __iter__(self):
        return self

    @mutex
    def __next__(self):
        if self.file.closed:
            raise StopIteration

        line = self.file.readline()
        if line == "":
            raise StopIteration

        self.row += 1
        return self.row, line

    @mutex
    def close(self):
        self.file.close()


reader  = Reader(args.file)
if args.batch:
    threads = []
    for _ in range(args.threads):
        w = threading.Thread(target=prepare_and_send, args=(reader,))
        w.start()
        threads.append(w)

    try:
        for w in threads:
            w.join()
    except KeyboardInterrupt:
        reader.close()
else:
    prepare_and_send(reader, single_file=True)
