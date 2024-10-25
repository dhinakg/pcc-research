import base64
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
)

SAVE_DIR = Path("releases")
SAVE_DIR.mkdir(exist_ok=True)

REQUEST_UUID = str(uuid.uuid4())

SESSION = requests.Session()
SESSION.verify = False
SESSION.headers = {"X-Apple-Request-UUID": REQUEST_UUID, "Content-Type": "application/protobuf"}


BAG_URL = "https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch"
BAG = plistlib.loads(SESSION.get(BAG_URL, timeout=3).content)


def get_trees():
    body = ListTreesRequest(ProtocolVersion.V3, REQUEST_UUID)

    resp = SESSION.post(
        BAG["at-researcher-list-trees"],
        data=bytes(body),
        timeout=5,
    )
    resp.raise_for_status()
    trees = ListTreesResponse().parse(resp.content)
    rich.print(trees)

    return trees


def get_log_head_for_tree(tree: ListTreesResponseTree):
    body = LogHeadRequest(ProtocolVersion.V3, tree.tree_id, -1, REQUEST_UUID)
    resp = SESSION.post(
        BAG["at-researcher-log-head"],
        data=bytes(body),
        timeout=5,
    )
    resp.raise_for_status()
    signed_log_head = LogHeadResponse().parse(resp.content)
    rich.print(signed_log_head)
    log_head = LogHead().parse(signed_log_head.log_head.object)
    rich.print(log_head)

    return log_head


def get_log_leaves(tree: ListTreesResponseTree, start_index: int, end_index: int):
    body = LogLeavesRequest(ProtocolVersion.V3, tree.tree_id, start_index, end_index, REQUEST_UUID, 0, tree.merge_groups)
    resp = SESSION.post(
        BAG["at-researcher-log-leaves"],
        data=bytes(body),
        timeout=5,
    )
    resp.raise_for_status()
    log_leaves = LogLeavesResponse().parse(resp.content)
    # rich.print(log_leaves)

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
    index: int
    expiry: datetime.datetime
    hash: Optional[bytes]
    assets: list[dict]
    tickets_raw: bytes
    ap_ticket: bytes
    cryptex_tickets: list[bytes]
    darwin_init: dict

    def __init__(self, log_leaf: LogLeavesResponseLeaf, at_leaf: ATLeaf) -> None:
        self.index = log_leaf.index
        self.expiry = at_leaf.expiry
        self.hash = at_leaf.hash
        release_metadata = ReleaseMetadata().parse(log_leaf.metadata)
        self.assets = [x.to_pydict() for x in release_metadata.assets]
        self.darwin_init = MessageToDict(struct_pb2.Struct.FromString(bytes(release_metadata.darwin_init)))

        self.tickets_raw = log_leaf.raw_data

        decoder = asn1.Decoder()
        decoder.start(log_leaf.raw_data)
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


def get_releases():
    trees = get_trees()

    selected_tree = None
    for tree in trees.trees:
        if tree.application == Application.PRIVATE_CLOUD_COMPUTE and tree.log_type == LogType.AT_LOG:
            assert selected_tree is None, "Multiple AT_LOG trees found"
            selected_tree = tree

    assert selected_tree is not None, "No AT_LOG tree found"
    rich.print(selected_tree)

    log_head = get_log_head_for_tree(selected_tree)

    start_index = 0
    end_index = log_head.log_size
    print(f"Log size: {end_index}")
    log_leaves = get_log_leaves(selected_tree, start_index, end_index)

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


def serializer(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode()
    elif isinstance(obj, (enum.Enum, betterproto.Enum)):
        assert False
        return obj.name
    # elif isinstance(obj, asn1.Object):
    #     return obj.dump()
    else:
        return obj


if __name__ == "__main__":
    releases = get_releases()

    for release in releases:
        rich.print(release)
        release_dir = SAVE_DIR / f"{release.index}"
        release_dir.mkdir(exist_ok=True)
        with (release_dir / "description.txt").open("w") as f:
            rich.print(release, file=f)
        (release_dir / "metadata.json").write_text(
            json.dumps(
                {i: v for i, v in dataclasses.asdict(release).items() if i in ["index", "expiry", "hash"]},
                indent=4,
                default=serializer,
            )
        )
        (release_dir / "assets.json").write_text(json.dumps(release.assets, indent=4, default=serializer))
        (release_dir / "darwin_init.json").write_text(json.dumps(release.darwin_init, indent=4, default=serializer))
        (release_dir / "tickets_raw.der").write_bytes(release.tickets_raw)
        (release_dir / "apticket.der").write_bytes(release.ap_ticket)

        cryptex_tickets_dir = release_dir / "cryptex_tickets"
        cryptex_tickets_dir.mkdir(exist_ok=True)
        for i, ticket in enumerate(release.cryptex_tickets):
            (cryptex_tickets_dir / f"cryptex_ticket_{i}.der").write_bytes(ticket)
