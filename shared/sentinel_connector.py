import datetime
import hashlib
import hmac
import json
import logging
import base64
from typing import Any, Iterable
import requests

class AzureSentinelConnector:
    def __init__(self, log_analytics_uri: str, workspace_id: str, shared_key: str, log_type: str, queue_size: int = 500):
        self.log_analytics_uri = log_analytics_uri.rstrip("/")
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.queue_size = queue_size
        self._buffer: list[dict[str, Any]] = []
        self.successfull_sent_events_number = 0

    def _build_signature(self, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        x_headers = f"x-ms-date:{date}"
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    def _post_data(self, body: str) -> requests.Response:
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        signature = self._build_signature(rfc1123date, len(body), method, content_type, resource)
        uri = f"{self.log_analytics_uri}{resource}?api-version=2016-04-01"
        headers = {
            'content-type': content_type,
            'Authorization': signature,
            'Log-Type': self.log_type,
            'x-ms-date': rfc1123date
        }
        return requests.post(uri, data=body, headers=headers, timeout=30)

    def send(self, record: dict[str, Any]):
        self._buffer.append(record)
        if len(self._buffer) >= self.queue_size:
            self.flush()

    def flush(self):
        if not self._buffer:
            return
        try:
            body = json.dumps(self._buffer, separators=(",", ":"))
            resp = self._post_data(body)
            if 200 <= resp.status_code < 300:
                self.successfull_sent_events_number += len(self._buffer)
            else:
                logging.error(f"Sentinel post failed: {resp.status_code} {resp.text}")
        except Exception as ex:
            logging.exception(f"Sentinel post exception: {ex}")
        finally:
            self._buffer = []