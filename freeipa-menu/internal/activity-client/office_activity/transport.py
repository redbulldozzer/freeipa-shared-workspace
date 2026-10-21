import json
from pathlib import Path
import ssl
import socket
import stat
import urllib.parse
import urllib.request
from . import __version__


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('ingestion_redirect_rejected')


def upload(store, config, token_path):
    endpoint = config.get('endpoint', '')
    if not endpoint:
        return 'local_only'
    url = urllib.parse.urlsplit(endpoint)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment or url.query:
        raise ValueError('endpoint_must_be_https')
    path = Path(token_path)
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError('token_permissions_must_be_0600')
    token = path.read_text().strip()
    if not token or '\n' in token or '\r' in token:
        raise ValueError('invalid_device_token')
    batch = store.pending(200)
    if not batch:
        return 'up_to_date'
    if any(e.get('device_id', config['device_id']) != config['device_id'] for e in batch):
        raise ValueError('queue_device_mismatch')
    context = ssl.create_default_context(cafile=config.get('ca_file') or None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(endpoint,
        data=json.dumps({'schema_version': 1, 'device_id': config['device_id'],
                         'hostname': socket.gethostname(), 'agent_version': __version__, 'events': batch}).encode(),
        headers={'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}, method='POST')
    with opener.open(request, timeout=10) as response:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('response_too_large')
        accepted = json.loads(raw).get('accepted_event_ids')
    ids = {e['event_id'] for e in batch}
    if not isinstance(accepted, list) or any(not isinstance(i, str) or i not in ids for i in accepted):
        raise ValueError('invalid_acknowledgement')
    store.acknowledge(accepted)
    return 'uploaded' if accepted else 'not_accepted'
