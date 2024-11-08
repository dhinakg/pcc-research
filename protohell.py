import dataclasses
import datetime
import enum
import hashlib
import io
import json
import plistlib
import uuid
from pathlib import Path
from typing import Optional

import asn1
import betterproto
import requests
import rich
import urllib3
from google.protobuf import struct_pb2
from google.protobuf.json_format import MessageToDict

from lib import (
    Application,
    AtLogDataType,
    ChangeLogNodeV2,
    ListTreesRequest,
    ListTreesResponse,
    ListTreesResponseTree,
    LogHead,
    LogHeadRequest,
    LogHeadResponse,
    LogLeavesRequest,
    LogLeavesResponse,
    LogLeavesResponseLeaf,
    LogType,
    NodeType,
    PerApplicationTreeNode,
    ProtocolVersion,
    ReleaseMetadata,
    ReleaseMetadataSchemaVersion,
    Status,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERBOSE = True

# Save responses to local cache
SAVE_TO_LOCAL_CACHE = True
# Save JSON conversions to local cache. Independent of SAVE_TO_LOCAL_CACHE
SAVE_JSON_TO_LOCAL_CACHE = True
# Sort saved responses if needed (list trees response)
SORT_SAVED_RESPONSES = True
# Fetch all trees, not just the release trees
FETCH_ALL_TREES = False
# Fetch top level tree, requires FETCH_ALL_TREES. Explicit flag as it is ~100MB
FETCH_TOP_LEVEL_TREE = False
# Number of leaves to fetch per request
LEAVES_PER_REQUEST = 10000

# Use local cache instead of fetching from server. Useful for parsing a dump.
LOAD_FROM_LOCAL_CACHE = False

# Serialize enums as strings instead of integers
SERIALIZE_AS_ENUM = True

# Only emit release-metadata.json files, no other release information
ONLY_RELEASE_METADATA = False

ROOT_DIR = Path("data")
TREES_DIR = ROOT_DIR / Path("trees")

REQUEST_UUID = str(uuid.uuid4())

SESSION = requests.Session()
SESSION.verify = False
SESSION.headers = {"X-Apple-Request-UUID": REQUEST_UUID, "Content-Type": "application/protobuf"}
TIMEOUT = 10


BAG_URL = "https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch"
BAG = plistlib.loads(SESSION.get(BAG_URL, timeout=TIMEOUT).content)


def write(path: Path, content: str | bytes):
    path.parent.mkdir(exist_ok=True, parents=True)
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_bytes(content)


def save_to_local_cache(path: Path, content: bytes):
    if SAVE_TO_LOCAL_CACHE:
        # path.write_bytes(content)
        write(path, content)


def save_json_to_local_cache(path: Path, content: betterproto.Message):
    if SAVE_JSON_TO_LOCAL_CACHE:
        # path.write_text(content.to_json(indent=4))
        write(path, content.to_json(indent=4))


def fetch_trees():
    if LOAD_FROM_LOCAL_CACHE:
        return (TREES_DIR / "list_trees_response.binpb").read_bytes()
    body = ListTreesRequest(ProtocolVersion.V3, REQUEST_UUID)

    resp = SESSION.post(
        BAG["at-researcher-list-trees"],
        data=bytes(body),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    if SORT_SAVED_RESPONSES:
        trees = ListTreesResponse().parse(resp.content)
        trees.trees.sort(key=lambda x: x.tree_id)
        save_to_local_cache(TREES_DIR / "list_trees_response.binpb", bytes(trees))
        return bytes(trees)
    else:
        save_to_local_cache(TREES_DIR / "list_trees_response.binpb", resp.content)
        return resp.content


def get_trees():
    raw = fetch_trees()
    trees = ListTreesResponse().parse(raw)
    save_json_to_local_cache(TREES_DIR / "list_trees_response.json", trees)

    for tree in trees.trees:
        save_json_to_local_cache(TREES_DIR / str(tree.tree_id) / "tree.json", tree)

    return trees


def fetch_log_head_for_tree(tree: ListTreesResponseTree):
    # Note: We save and load the log head rather than the signed object, as we do not need the signature
    if LOAD_FROM_LOCAL_CACHE:
        return (TREES_DIR / str(tree.tree_id) / "log_head.binpb").read_bytes()
    body = LogHeadRequest(ProtocolVersion.V3, tree.tree_id, -1, REQUEST_UUID)
    resp = SESSION.post(
        BAG["at-researcher-log-head"],
        data=bytes(body),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    signed_log_head = LogHeadResponse().parse(resp.content)
    save_to_local_cache(TREES_DIR / str(tree.tree_id) / "log_head.binpb", signed_log_head.log_head.object)
    return signed_log_head.log_head.object


def get_log_head_for_tree(tree: ListTreesResponseTree):
    raw = fetch_log_head_for_tree(tree)
    log_head = LogHead().parse(raw)
    save_json_to_local_cache(TREES_DIR / str(tree.tree_id) / "log_head.json", log_head)

    return log_head


def fetch_log_leaves(tree: ListTreesResponseTree, start_index: int, end_index: int):
    if LOAD_FROM_LOCAL_CACHE:
        return (TREES_DIR / str(tree.tree_id) / "log_leaves.binpb").read_bytes()

    leaves_response = None

    current = start_index
    while current < end_index:
        current_end = min(current + LEAVES_PER_REQUEST, end_index)
        rich.print(f"Fetching {tree.log_type} {tree.tree_id} leaves {current} to {current_end}")
        body = LogLeavesRequest(ProtocolVersion.V3, tree.tree_id, current, current_end, REQUEST_UUID, 0, tree.merge_groups)
        resp = SESSION.post(
            BAG["at-researcher-log-leaves"],
            data=bytes(body),
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        log_leaves = LogLeavesResponse().parse(resp.content)

        if not leaves_response:
            leaves_response = log_leaves
        else:
            leaves_response.leaves.extend(log_leaves.leaves)

        current = current_end

    assert leaves_response

    raw = bytes(leaves_response)
    save_to_local_cache(TREES_DIR / str(tree.tree_id) / "log_leaves.binpb", raw)
    return raw


def get_log_leaves(tree: ListTreesResponseTree, start_index: int, end_index: int):
    raw = fetch_log_leaves(tree, start_index, end_index)
    log_leaves = LogLeavesResponse().parse(raw)
    assert log_leaves.status == Status.OK
    save_json_to_local_cache(TREES_DIR / str(tree.tree_id) / "log_leaves.json", log_leaves)

    return log_leaves


@dataclasses.dataclass
class TransparencyExtension:
    type: int
    data: bytes


@dataclasses.dataclass
class ATLeaf:
    version: int
    type: AtLogDataType
    description: Optional[str]
    hash: Optional[bytes]
    expiry_ms: int
    extensions: list[TransparencyExtension]

    @property
    def expiry(self):
        return datetime.datetime.fromtimestamp(self.expiry_ms / 1000, datetime.timezone.utc)


def parse_at_leaf(raw: bytes):
    with io.BytesIO(raw) as stream:
        version = stream.read(1)[0]
        type = AtLogDataType(stream.read(1)[0])  # pylint: disable=missing-kwoa,too-many-function-args
        description_size = stream.read(1)[0]
        description = stream.read(description_size).decode() or None
        hash_size = stream.read(1)[0]
        hash = stream.read(hash_size) or None
        expiry_ms = int.from_bytes(stream.read(8), "big")
        extensions_size = int.from_bytes(stream.read(2), "big")
        extensions_raw = stream.read(extensions_size)

        extensions = []

        with io.BytesIO(extensions_raw) as extensions_stream:
            while extensions_stream.tell() < extensions_size:
                extension_type = extensions_stream.read(1)[0]
                extension_size = int.from_bytes(extensions_stream.read(2), "big")
                extension_data = extensions_stream.read(extension_size)
                extension = TransparencyExtension(extension_type, extension_data)
                extensions.append(extension)

    return ATLeaf(version, type, description, hash, expiry_ms, extensions)


# For some reason, this is called a Release in the code, even though the name overlaps with the Release class from SWReleases
# Ironically, it is aliased to Tickets there, so that is what we will call it here
def parse_tickets(raw: bytes):
    decoder = asn1.Decoder()
    decoder.start(raw)
    tag = decoder.peek()
    assert tag.nr == asn1.Numbers.Sequence
    decoder.enter()

    tag, version = decoder.read()
    assert tag.nr == asn1.Numbers.Integer
    assert version == 1

    tag, ap_ticket = decoder.read()
    assert tag.nr == asn1.Numbers.OctetString
    ap_ticket: bytes = ap_ticket

    tag = decoder.peek()
    assert tag.nr == asn1.Numbers.Set
    cryptex_tickets = []
    decoder.enter()

    while not decoder.eof():
        tag, cryptex_ticket = decoder.read()
        assert tag.nr == asn1.Numbers.OctetString
        cryptex_tickets.append(cryptex_ticket)

    return ap_ticket, cryptex_tickets


@dataclasses.dataclass(init=False)
class Release:
    release_metadata_present: bool = False
    schema: Optional[ReleaseMetadataSchemaVersion] = None
    index: int
    created: Optional[datetime.datetime] = None
    expires: Optional[datetime.datetime] = None
    hash: Optional[bytes]
    assets: Optional[list[dict]] = None
    tickets_raw: bytes
    ap_ticket: bytes
    cryptex_tickets: list[bytes]
    darwin_init: Optional[dict] = None

    def __init__(self, log_leaf: LogLeavesResponseLeaf, at_leaf: ATLeaf) -> None:
        self.index = log_leaf.index
        self.expires = at_leaf.expiry
        self.hash = at_leaf.hash
        if log_leaf.metadata:
            self.release_metadata_present = True
            release_metadata = ReleaseMetadata().parse(log_leaf.metadata)
            self.schema = release_metadata.schema_version
            self.created = release_metadata.timestamp
            self.assets = [x.to_pydict() for x in release_metadata.assets]
            self.darwin_init = MessageToDict(struct_pb2.Struct.FromString(bytes(release_metadata.darwin_init)))  # pylint: disable=no-member

        self.tickets_raw = log_leaf.raw_data
        assert self.tickets_raw
        self.ap_ticket, self.cryptex_tickets = parse_tickets(self.tickets_raw)


def get_releases_from_leaves(log_leaves: LogLeavesResponse):
    releases: list[Release] = []

    for log_leaf in log_leaves.leaves:
        if log_leaf.node_type == NodeType.ATL_NODE:
            raw_data = log_leaf.raw_data
            change_log_node = ChangeLogNodeV2().parse(log_leaf.node_bytes)
            at_leaf = parse_at_leaf(change_log_node.mutation)

            if raw_data:
                assert hashlib.sha256(raw_data).digest() == at_leaf.hash, "Hash mismatch"

            if at_leaf.type == AtLogDataType.RELEASE:
                release = Release(log_leaf, at_leaf)
                releases.append(release)

    return releases


def convert_enum_to_name(obj):
    if not SERIALIZE_AS_ENUM:
        return obj

    if isinstance(obj, (enum.Enum, betterproto.Enum)):
        return obj.name
    elif isinstance(obj, list):
        return [convert_enum_to_name(x) for x in obj]
    elif isinstance(obj, dict):
        return {k: convert_enum_to_name(v) for k, v in obj.items()}
    else:
        return obj


class ReleaseEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        elif isinstance(o, bytes):
            return o.hex()
        else:
            return super().default(o)


def process_releases(tree_path: Path, log_leaves: LogLeavesResponse):
    for release in get_releases_from_leaves(log_leaves):
        if VERBOSE:
            rich.print(release)

        release_dir = tree_path / "releases" / f"{release.index}"
        if not ONLY_RELEASE_METADATA:
            write(
                release_dir / "metadata.json",
                json.dumps(
                    convert_enum_to_name(
                        {
                            i: v
                            for i, v in dataclasses.asdict(release).items()
                            if i not in ["assets", "tickets_raw", "ap_ticket", "cryptex_tickets", "darwin_init"]
                        }
                        | {
                            "tickets": {
                                "os": hashlib.sha256(release.ap_ticket).hexdigest(),
                                "cryptexes": [hashlib.sha256(x).hexdigest() for x in release.cryptex_tickets],
                            }
                        }
                    ),
                    indent=4,
                    cls=ReleaseEncoder,
                ),
            )
            if release.assets:
                write(release_dir / "assets.json", json.dumps(convert_enum_to_name(release.assets), indent=4, cls=ReleaseEncoder))
            if release.darwin_init:
                write(release_dir / "darwin_init.json", json.dumps(release.darwin_init, indent=4, cls=ReleaseEncoder))
            write(release_dir / "tickets_raw.der", release.tickets_raw)
            write(release_dir / "apticket.der", release.ap_ticket)

            cryptex_tickets_dir = release_dir / "cryptex_tickets"
            for i, ticket in enumerate(release.cryptex_tickets):
                write(cryptex_tickets_dir / f"cryptex_ticket_{i}.der", ticket)

        if release.release_metadata_present:
            assert release.created
            write(
                release_dir / "release-metadata.json",
                json.dumps(
                    {
                        "assets": convert_enum_to_name(release.assets),
                        "darwinInit": release.darwin_init,
                        "schemaVersion": convert_enum_to_name(release.schema),
                        "timestamp": release.created.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                    indent=2,
                    sort_keys=True,
                    cls=ReleaseEncoder,
                ),
            )


def get_log_heads_from_leaves(log_leaves: LogLeavesResponse):
    log_heads: list[LogHead] = []

    for log_leaf in log_leaves.leaves:
        if log_leaf.node_type == NodeType.PAT_NODE:
            pat_node = PerApplicationTreeNode().parse(log_leaf.node_bytes)
            log_head = LogHead().parse(pat_node.predecessor_head.object)
            log_heads.append(log_head)

    return log_heads


def process_log_heads(tree_path: Path, log_leaves: LogLeavesResponse):
    log_heads = get_log_heads_from_leaves(log_leaves)
    if not log_heads:
        return

    for log_head in log_heads:
        if VERBOSE:
            rich.print(log_head)

    log_heads_path = tree_path / "log_heads.json"
    write(log_heads_path, json.dumps([x.to_dict() for x in log_heads], indent=4))


def main():
    trees = get_trees()

    for tree in trees.trees:
        target = tree.application == Application.PRIVATE_CLOUD_COMPUTE and tree.log_type == LogType.AT_LOG
        if target or FETCH_ALL_TREES:
            log_head = get_log_head_for_tree(tree)

            if tree.log_type == LogType.TOP_LEVEL_TREE and not FETCH_TOP_LEVEL_TREE:
                continue

            start_index = 0
            end_index = log_head.log_size
            log_leaves = get_log_leaves(tree, start_index, end_index)

            tree_save_path = TREES_DIR / str(tree.tree_id)

            process_releases(tree_save_path, log_leaves)
            process_log_heads(tree_save_path, log_leaves)


if __name__ == "__main__":
    main()
