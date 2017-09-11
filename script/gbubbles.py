#! /usr/bin/python3

import argparse
import base64
import datetime
import hashlib
import logging
import os
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from xml.etree import ElementTree

import requests
from gcloud import storage
from zeep.wsse import utils


# Constants
STATUS_SUCCESS = "SUCCESS"
STATUS_PARTIAL = "PARTIAL"
STATUS_ERROR   = "ERROR"
STATUS_EMPTY   = ""
STAGER         = 0.25

STATUS_LOGGING_LEVELS = {
    STATUS_SUCCESS : logging.INFO,
    STATUS_PARTIAL : logging.WARN,
    STATUS_ERROR   : logging.ERROR,
}

# Logging config
logger    = logging.getLogger(__name__)
handler   = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s | %(levelname)7s | %(message)s')
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument("--env",      type=str,  default="local",       help="key in the env map [local, dev, stage, sandbox, prod]")
parser.add_argument("--username", type=str,  default="",            help="used to overwrite env value")
parser.add_argument("--password", type=str,  default="",            help="used to overwrite env value")
parser.add_argument("--batch",    action="store_true",              help="to execute multiple lines from the file")
parser.add_argument("--file",     type=str,                         help="relative location of the file where payloads are located")
parser.add_argument("--threads",  type=int,  default=1,             help="number of threads to use")
parser.add_argument("--skip",     type=str,  nargs="+", default=[], help="transaction types to skip")
args = parser.parse_args()

re_type     = re.compile('transactionType="(\w+)"',                   re.DOTALL | re.IGNORECASE)
re_status   = re.compile('responseCode="(\w+)"',                      re.DOTALL | re.IGNORECASE)
re_pnr      = re.compile('recordLocatorNumber="(\w+)"',               re.DOTALL | re.IGNORECASE)
re_errors   = re.compile('ErrorMessage message="(.*)"/>',             re.DOTALL | re.IGNORECASE)
re_body     = re.compile('<soap-env:body>(.*)</soap-env:body>',       re.DOTALL | re.IGNORECASE)
re_security = re.compile('<soap:Text xml:lang=".+">(.*)</soap:Text>', re.DOTALL | re.IGNORECASE)

endpoint    = "trs/TravelReservationSyncEndpointBinding?wsdl"

try:
    from config import env
    logger.info("Env map from config")
except ImportError:
    env = {
        "local": {
            "host"    : "http://localhost:5052",  # change port to match local env
            "username": "test1",
            "password": "testpassword1",
        },
        "dev": {
            "host"    : "http://api-soap-dev.flyrlabs.com",
            "username": "test1",
            "password": "testpassword1",
        },
        "stage": {
            "host"    : "http://api-soap-staging.flyrlabs.com",
            "username": "test1",
            "password": "testpassword1",
        },
        "sandbox": {
            "host"    : "http://api-soap-sandbox.flyrlabs.com",
        },
        "prod": {
            "host"    : "http://api-soap.flyrlabs.com",
        }
    }
    logger.info("Env map from script")

env      = env.get(args.env, None)
host     = env.get("host", "")
username = env.get("username", "") if not args.username else args.username
password = env.get("password", "") if not args.password else args.password
to_skip  = set(map(lambda x: x.upper(), args.skip))

logger.info("Arguments used    : {}".format(args))
logger.info("Env               : {}".format(env))
logger.info("Endpoint          : {}/{}".format(host, endpoint))
logger.info("Username/password : {} {}".format(username, password))
logger.info("======================================================")


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


def mutex(func):
    def wrapper(self, *args, **kwargs):
        self.lock.acquire()
        try:
            data = func(self, *args, **kwargs)
        except StopIteration as e:
            raise e
        else:
            return data
        finally:
            self.lock.release()
    return wrapper


class Cloud(object):

    def __init__(self, prefix, project="flyr-datascience", bucket="flyr_cwt1", env="local"):
        self.bucket = bucket
        self.prefix = prefix
        self.bucket = storage.Client(project).get_bucket(bucket)
        self.blobs  = deque(self.bucket.list_blobs(prefix=self.prefix))
        self.passwd = 'flYr_*%1'
        self.env    = env

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            blob = None
            i = 0
            while len(self.blobs) > 0:
                blob = self.blobs.popleft()
                i += 1
                if len(blob.name) < 30:
                    logger.warning("Skipping {:s}".format(blob.name))
                    continue
                break

            if blob is None:
                raise StopIteration

            self.current_blob = blob

            _, name = os.path.split(blob.name)
            path = os.path.join("/tmp", name)

            logger.info("Downloading {}".format(blob.name))
            blob.download_to_filename(os.path.join("/tmp", name))
            resp = subprocess.call(["7z", "x", path, "-o/tmp", "-p{}".format(self.passwd), "-y"])
            if resp != 0:
                logger.warning("Unzipped {:s} with error code {:d}".format(path, resp))
                os.unlink(path)
                self.problem_unzipping(resp)
                continue
            return open(".".join([os.path.splitext(path)[0], "txt"]), "r")

    def problem_unzipping(self, code):
        if self.env == "prod":
            self.bucket.rename_blob(self.current_blob, "errors/{:d}/{}".format(self.blob.name))
            logger.info("Problem ({:d}) {:s}".format(code, self.current_blob.name))

    def mark_completed(self):
        if self.env == "prod":
            self.bucket.rename_blob(self.current_blob, "completed/{}".format(self.blob.name))
        logger.info("Completed {:s}".format(self.current_blob.name))


class Reader(object):

    def __init__(self, cloud):
        self.cloud  = cloud
        self.lock   = threading.Lock()
        self.stats  = defaultdict(lambda: defaultdict(float))
        self.pnrs   = set()
        self.row    = 0
        self.f      = self.cloud.__next__()
        self.closed = False

    def __iter__(self):
        return self

    @mutex
    def memory(self, pnr):
        if pnr in self.pnrs:
            return True
        else:
            self.pnrs.add(pnr)
            return False

    def _get_new_file(self):
        self.f = self.cloud.__next__()
        self.row = 0
        if self.f is None:
            return False
        return True

    @mutex
    def __next__(self):
        while not self.closed:
            line = self.f.readline()
            if line == "":
                self.cloud.mark_completed()
                if self._get_new_file():
                    continue
                raise StopIteration
            self.row += 1
            return self.row, line
        return -1, ""

    @mutex
    def close(self):
        self.closed = True

    @mutex
    def score(self, dt, status):
        self.stats[status]["timing"] += dt
        self.stats[status]["count"]  += 1

    def print_stats(self):
        fmt = "{status:>10}: {count:>6.0f} requests in {timing:>8.2f}s"
        logger.info("{} stat summary {}".format(*("=" * 20, "=" * 20)))

        total_requests, total_time = 0, 0
        for status, info in self.stats.items():
            total_requests += info.get("count")
            total_time     += info.get("timing")
            logger.debug(fmt.format(status=status, **info))

        logger.debug(fmt.format(status="total", count=total_requests, timing=total_time))


def worker(reader, single_file=False):
    for index, line in reader:

        if index == -1 and line == "":
            logger.info("Shutting down")
            break

        transaction_type = re_type.findall(line)
        intersection = to_skip.intersection(set(transaction_type))
        if len(intersection):
            logger.info("{:>6d}: {} marked for skip".format(index, transaction_type))
            continue

        matches = re_body.findall(line)
        if len(matches) != 1:
            logger.error("{:>6d}: invalid number of <soap-env:body> sections. expected 1 found {:d}".format(index, len(matches)))
            reader.score(0, "BODY COUNT")
            continue

        # Don't do PNRs we've seen before
        try:
            pnr = re_pnr.findall(line)[0]
        except IndexError:
            logger.error("{:>6d}: cannot get pnr from line".format(index))
            continue
        else:
            if reader.memory(pnr):
                logger.info("{:>6d}: {} seen pnr, skipping".format(index, pnr))
                continue

        data = "".join(envelope.format(**{
            "security": security.apply(),
            "body"    : matches[0],
        }).split("\n"))

        tic      = time.time()
        response = requests.post(url, data=data, headers=headers)
        toc      = time.time()

        content = response.content.decode("ascii")
        status  = re_status.findall(content)
        if len(status):
            status = status.pop()
        else:
            status = "UNKNOWN"
        level = STATUS_LOGGING_LEVELS.get(status, logging.ERROR)

        dt = toc - tic
        message = []
        if level == logging.INFO:
            message = re_errors.findall(content)
        elif level == logging.WARN:
            message = re_errors.findall(content)
        else:
            message = re_security.findall(content)

        logger.log(level, "{:>6d}: {} {} in {:>5.2f}s with message: {}".format(index, pnr, status, dt, message))

        reader.score(dt, status)

        if single_file:
            return


def run_workers():
    cloud  = Cloud("xml_pnr_ftp_feed")
    reader = Reader(cloud)
    if args.batch:
        threads = []
        logger.info("starting {:d} worker{:s}".format(args.threads, "" if args.threads == 1 else "s"))
        for _ in range(args.threads):
            w = threading.Thread(target=worker, args=(reader,))
            w.start()
            time.sleep(STAGER)
            threads.append(w)

        try:
            for w in threads:
                w.join()
        except KeyboardInterrupt:
            reader.close()
    else:
        cloud  = Cloud("xml_pnr_ftp_feed")
        reader = Reader(cloud)
        reader.close()

    while threading.active_count() > 1:
        time.sleep(.1)

    reader.print_stats()


run_workers()
