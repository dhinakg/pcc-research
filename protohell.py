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
    ProtocolVersion,
    ReleaseMetadata,
    ReleaseMetadataSchemaVersion,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERBOSE = True

# Save responses to local cache
SAVE_TO_LOCAL_CACHE = True
# Save JSON conversions to local cache. Independent of SAVE_TO_LOCAL_CACHE
SAVE_JSON_TO_LOCAL_CACHE = True
# Fetch all trees, not just the release trees
FETCH_ALL_TREES = False

# Use local cache instead of fetching from server. Useful for parsing a dump.
LOAD_FROM_LOCAL_CACHE = False

# Serialize enums as strings instead of integers
SERIALIZE_AS_ENUM = True

# Only emit release-metadata.json files, no other release information
ONLY_RELEASE_METADATA = False

ROOT_DIR = Path("data")
TREES_DIR = ROOT_DIR / Path("trees")
RELEASES_DIR = ROOT_DIR / Path("releases")

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
    body = LogLeavesRequest(ProtocolVersion.V3, tree.tree_id, start_index, end_index, REQUEST_UUID, 0, tree.merge_groups)
    resp = SESSION.post(
        BAG["at-researcher-log-leaves"],
        data=bytes(body),
        timeout=TIMEOUT,
    )
    resp.raise_for_status()
    save_to_local_cache(TREES_DIR / str(tree.tree_id) / "log_leaves.binpb", resp.content)
    return resp.content


def get_log_leaves(tree: ListTreesResponseTree, start_index: int, end_index: int):
    raw = fetch_log_leaves(tree, start_index, end_index)
    log_leaves = LogLeavesResponse().parse(raw)
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

        decoder = asn1.Decoder()
        decoder.start(self.tickets_raw)
        tag = decoder.peek()
        assert tag.nr == asn1.Numbers.Sequence
        decoder.enter()

        tag, version = decoder.read()
        assert tag.nr == asn1.Numbers.Integer
        assert version == 1

        tag, ap_ticket = decoder.read()
        assert tag.nr == asn1.Numbers.OctetString
        self.ap_ticket: bytes = ap_ticket

        tag = decoder.peek()
        assert tag.nr == asn1.Numbers.Set
        self.cryptex_tickets = []
        decoder.enter()

        while not decoder.eof():
            tag, cryptex_ticket = decoder.read()
            assert tag.nr == asn1.Numbers.OctetString
            self.cryptex_tickets.append(cryptex_ticket)


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


if __name__ == "__main__":
    releases = []

    trees = get_trees()

    for tree in trees.trees:
        target = tree.application == Application.PRIVATE_CLOUD_COMPUTE and tree.log_type == LogType.AT_LOG
        if target or FETCH_ALL_TREES:
            log_head = get_log_head_for_tree(tree)

            if tree.log_type == LogType.TOP_LEVEL_TREE:
                # Fetching the log leaves for the top level tree is currently not supported, as there are too many
                # and the server will return an error
                # TODO: Add pagination
                continue

            start_index = 0
            end_index = log_head.log_size
            log_leaves = get_log_leaves(tree, start_index, end_index)

            if target:
                releases = get_releases_from_leaves(log_leaves)

    for release in releases:
        if VERBOSE:
            rich.print(release)

        release_dir = RELEASES_DIR / f"{release.index}"
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
