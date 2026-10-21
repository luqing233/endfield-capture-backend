"""Explicitly verified client builds; unknown binaries must fail closed."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientProfile:
    channel: str
    dll_sha256: str
    metadata_sha256: str
    key_literal_rva: int
    modulus_filename: str


CN_PROFILE = ClientProfile(
    "cn",
    "ab00f1c41e13edf9816f142b166e3c2536d5bc7707992c39e5ed52d1cc888e2c",
    "461321d9dca6a832bce3bd2390402efc7c83c145554e97a8058bb68fbec1c8ca",
    0x10657230,
    "rsa_modulus.json",
)
INTERNATIONAL_PROFILE = ClientProfile(
    "international",
    "bfedade1a1964a6fd1bb9fe2f36eec38a47472d7d76ff868d3331c5d70234959",
    CN_PROFILE.metadata_sha256,
    0x10657230,
    "rsa_modulus_international.json",
)
CLIENT_PROFILES = {profile.dll_sha256: profile for profile in (CN_PROFILE, INTERNATIONAL_PROFILE)}


def profile_for_digest(digest: str) -> ClientProfile:
    try:
        return CLIENT_PROFILES[digest]
    except KeyError:
        raise ValueError(f"客户端版本已改变，需要重新核对解码入口（GameAssembly.dll sha256={digest}）") from None


def modulus_data_path(profile: ClientProfile) -> Path:
    return Path(__file__).with_name("data") / profile.modulus_filename
