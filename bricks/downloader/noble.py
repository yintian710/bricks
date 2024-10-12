# -*- coding: utf-8 -*-
"""
@File    : noble.py
@Date    : 2024/7/3 下午11:05
@Author  : yintian
@Desc    : 
"""
import asyncio
import copy
import urllib.parse
from typing import Union

import noble_tls
from noble_tls import Client

from bricks import Request, Response
from bricks.downloader import AbstractDownloader
from bricks.lib.cookies import Cookies
from bricks.utils.pandora import json_or_eval


class Downloader(AbstractDownloader):
    """
    对 noble-tls 进行的一层包装, 支持手动设置 tls
    兼容 Windows / Mac / Linux

    """

    def __init__(self, impersonate: Union[Client, str] = None, tls_config: [dict, ] = None) -> None:
        self.impersonate = impersonate
        self.tls_config = tls_config

    async def fetch(self, request: Union[Request, dict]) -> Response:
        res = Response.make_response(request=request)
        options = {
            'method': request.method.upper(),
            'headers': request.headers,
            'cookies': request.cookies,
            "data": self.parse_data(request)['data'],
            'timeout_seconds': 5 if request.timeout is ... else request.timeout,
            'allow_redirects': False,
            'proxy': request.proxies and {"http": request.proxies, "https": request.proxies},  # noqa
            'insecure_skip_verify': request.options.get("verify", False),
        }
        impersonate = request.get_options('impersonate', self.impersonate)
        tls_config = request.get_options('tls_config', self.tls_config)
        _session_options = request.get_options('session_options', {})
        if tls_config:
            session_options = {
                **to_tls_config(tls_config)
            }
        elif impersonate:
            if isinstance(impersonate, str):
                impersonate = Client(impersonate)
            session_options = {
                'client': impersonate
            }
        else:
            session_options = {}
        session_options = {
            'random_tls_extension_order': True,
            **session_options,
            **_session_options
        }
        session = noble_tls.Session(
            **session_options
        )

        next_url = request.real_url
        _redirect_count = 0

        while True:
            assert _redirect_count < 999, "已经超过最大重定向次数: 999"
            response = await session.execute_request(
                url=next_url,
                **options
            )
            last_url, next_url = next_url, response.headers.get('location') or response.headers.get('Location')
            if request.allow_redirects and next_url:
                next_url = urllib.parse.urljoin(response.url, next_url)
                _redirect_count += 1
                res.history.append(
                    Response(
                        content=response.content,
                        headers=response.headers,
                        cookies=Cookies(response.cookies),
                        url=response.url,
                        status_code=response.status_code,
                        request=Request(
                            url=last_url,
                            method=request.method,
                            headers=copy.deepcopy(options.get('headers', {}))
                        )
                    )
                )
                request.options.get('$referer', False) and options['headers'].update(Referer=response.url)
            else:
                res.content = response.content
                res.headers = response.headers
                res.cookies = Cookies(response.cookies)
                res.url = response.url
                res.status_code = response.status_code
                res.request = request
                return res


def to_tls_config(ja3_config: Union[str, dict]):
    if isinstance(ja3_config, str):
        ja3_config = json_or_eval(ja3_config)
    _config = {
        "force_http1": False,
        "ja3_string": get_ja3_string(ja3_config),
        "h2_settings": get_h2_settings(ja3_config),
        "h2_settings_order": get_h2_settings_order(ja3_config),
        "connection_flow": get_connection_flow(ja3_config),
        "priority_frames": get_priority_frames(ja3_config),
        "header_priority": get_header_priority(ja3_config),
        "supported_signature_algorithms": get_supported_signature_algorithms(ja3_config),
        "supported_versions": get_supported_versions(ja3_config),
        "key_share_curves": get_key_share_curves(ja3_config),
        "supported_delegated_credentials_algorithms": get_supported_delegated_credentials_algorithms(ja3_config),
        "cert_compression_algo": get_cert_compression_algo(ja3_config),
        "additional_decode": None,
        "catch_panics": None,
        "pseudo_header_order": None,
        # "cert_compression_algo": "brotli",
        # "PSKKeyExchangeModes": get_psk_key_exchange_modes(ja3_config),
        # "RecordSizeLimit": get_record_size_limit(ja3_config),
        # "SignatureAlgorithmsCert": get_signature_algorithms_cert(ja3_config),
        # "NotUsedGREASE": get_not_used_grease(ja3_config),
    }
    config = {k: v for k, v in _config.items() if v}
    return config


def get_ja3_string(config):
    ja3_string = config["tls"]["ja3"]
    return ja3_string


def get_header_order(config):
    headers = {}
    headers_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            headers_list = sent_frame["headers"]
            break
    for header in headers_list:
        if header[0] == ":":
            continue
        key, value = header.split(":", 1)
        key = key.strip()
        value = value.strip()
        headers[key] = value
    return list(headers.keys())


def get_force_http1(config):
    force_http1 = False
    if config["http_version"] != "h2":
        force_http1 = True
    return force_http1


def get_pseudo_header_order(config):
    headers = {}
    headers_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            headers_list = sent_frame["headers"]
            break
    for header in headers_list:
        if header[0] == ":":
            key, value = header.split(":")[1:]
            key = ":" + key.strip()
            value = value.strip()
            headers[key] = value
    return list(headers.keys())


def get_supported_signature_algorithms(config):
    supported_signature_algorithms = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if extension.get("signature_algorithms", False):
            signature_algorithms = extension["signature_algorithms"]
            for signature_algorithm in signature_algorithms:
                supported_signature_algorithms.append(signature_algorithm)
    if supported_signature_algorithms:
        return supported_signature_algorithms
    return None


def get_cert_compression_algo(config):
    cert_compression_algo = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "compress_certificate" in extension["name"]:
            for algorithm in extension["algorithms"]:
                if not cert_compression_algo:
                    cert_compression_algo = []
                cert_compression_algo.append(algorithm.split("(", 1)[0].strip())
    return "".join(cert_compression_algo)


def get_record_size_limit(config):
    record_size_limit = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "record_size_limit" in extension["name"]:
            record_size_limit = int(extension["data"])
    return record_size_limit


def get_supported_delegated_credentials_algorithms(config):
    supported_delegated_credentials_algorithms = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if extension.get("signature_hash_algorithms", False):
            delegated_credentials_algorithms = extension["signature_hash_algorithms"]
            for delegated_credentials_algorithm in delegated_credentials_algorithms:
                supported_delegated_credentials_algorithms.append(delegated_credentials_algorithm)
    if supported_delegated_credentials_algorithms:
        return supported_delegated_credentials_algorithms
    return None


def get_supported_versions(config):
    supported_versions = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "supported_versions" in extension["name"]:
            versions = extension["versions"]
            for version in versions:
                key = version
                if "TLS_" in key:
                    key = key.split("TLS_", 1)[-1]
                elif "TLS " in key:
                    key = key.split("TLS ", 1)[-1]
                key = key.split("(", 1)[0]
                key = key.strip()
                supported_versions.append(key)
    if supported_versions:
        return supported_versions
    return None


def get_psk_key_exchange_modes(config):
    psk_key_exchange_modes = None
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "psk_key_exchange_modes" in extension["name"]:
            if not psk_key_exchange_modes:
                psk_key_exchange_modes = []
            if extension.get("PSK_Key_Exchange_Mode", ""):
                if extension["PSK_Key_Exchange_Mode"].endswith("(0)"):
                    psk_key_exchange_modes.append("PskModePlain")
                else:
                    psk_key_exchange_modes.append("PskModeDHE")
    return psk_key_exchange_modes


# 没法实现
def get_signature_algorithms_cert(config):
    pass


def get_key_share_curves(config):
    key_share_curves = []
    extensions = config["tls"]["extensions"]
    for extension in extensions:
        if "key_share" in extension["name"]:
            shared_keys = extension["shared_keys"]
            for shared_key in shared_keys:
                key = list(shared_key.keys())[0]
                key = key.split("TLS_", 1)[-1]
                key = key.split("(", 1)[0]
                key = key.strip()
                key = key.replace("-", "")
                key_share_curves.append(key)
    if key_share_curves:
        return key_share_curves
    return None


def get_not_used_grease(config):
    not_used_grease = False
    if "TLS_GREASE" not in config["tls"]["extensions"][0]["name"]:
        not_used_grease = True
    return not_used_grease


def get_h2_settings(config):
    settings = {}
    setting_list = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "SETTINGS":
            setting_list = sent_frame["settings"]
    for setting in setting_list:
        key, value = setting.split("=", 1)
        key = key.strip()
        value = value.strip()
        settings[key] = int(value)
    if settings:
        return settings
    return None


def get_h2_settings_order(config):
    settings = get_h2_settings(config)
    return list(settings.keys())


def get_connection_flow(config):
    connection_flow = None
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "WINDOW_UPDATE":
            connection_flow = sent_frame["increment"]
            break
    return connection_flow


def get_header_priority(config):
    header_priority = None
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "HEADERS":
            if sent_frame.get("priority", False):
                priority = sent_frame["priority"]
                header_priority = {
                    "weight": int(priority["weight"] / 2 - 1),
                    "streamDep": priority["depends_on"],
                    "exclusive": True if priority["exclusive"] else False
                }
                break
    return header_priority


def get_priority_frames(config):
    priority_frames = []
    sent_frames = config["http2"]["sent_frames"]
    for sent_frame in sent_frames:
        if sent_frame["frame_type"] == "PRIORITY":
            priority = sent_frame["priority"]
            priority_frame = {
                "streamID": sent_frame["stream_id"],
                "priorityParam": {
                    "weight": priority["weight"],
                    "streamDep": priority["depends_on"],
                    "exclusive": True if priority["exclusive"] else False
                }
            }
            priority_frames.append(priority_frame)
    if priority_frames:
        return priority_frames
    return None


async def main():
    # downloader1 = Downloader(
    #     impersonate='chrome_103',
    # )
    # rsp1 = await downloader1.fetch(Request(url="https://tls.peet.ws/api/all"))
    downloader2 = Downloader(
        tls_config={
            "ip": "18.162.194.225:6349",
            "http_version": "h2",
            "method": "GET",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "tls": {
                "ciphers": [
                    "TLS_GREASE (0xEAEA)",
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
                    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
                ],
                "extensions": [
                    {
                        "name": "TLS_GREASE (0x1a1a)"
                    },
                    {
                        "name": "server_name (0)",
                        "server_name": "tls.peet.ws"
                    },
                    {
                        "name": "extended_master_secret (23)",
                        "master_secret_data": "",
                        "extended_master_secret_data": ""
                    },
                    {
                        "name": "extensionRenegotiationInfo (boringssl) (65281)",
                        "data": "00"
                    },
                    {
                        "name": "supported_groups (10)",
                        "supported_groups": [
                            "TLS_GREASE (0xdada)",
                            "X25519 (29)",
                            "P-256 (23)",
                            "P-384 (24)",
                            "P-521 (25)"
                        ]
                    },
                    {
                        "name": "ec_point_formats (11)",
                        "elliptic_curves_point_formats": [
                            "0x00"
                        ]
                    },
                    {
                        "name": "application_layer_protocol_negotiation (16)",
                        "protocols": [
                            "h2",
                            "http/1.1"
                        ]
                    },
                    {
                        "name": "status_request (5)",
                        "status_request": {
                            "certificate_status_type": "OSCP (1)",
                            "responder_id_list_length": 0,
                            "request_extensions_length": 0
                        }
                    },
                    {
                        "name": "signature_algorithms (13)",
                        "signature_algorithms": [
                            "ecdsa_secp256r1_sha256",
                            "rsa_pss_rsae_sha256",
                            "rsa_pkcs1_sha256",
                            "ecdsa_secp384r1_sha384",
                            "ecdsa_sha1",
                            "rsa_pss_rsae_sha384",
                            "rsa_pss_rsae_sha384",
                            "rsa_pkcs1_sha384",
                            "rsa_pss_rsae_sha512",
                            "rsa_pkcs1_sha512",
                            "rsa_pkcs1_sha1"
                        ]
                    },
                    {
                        "name": "signed_certificate_timestamp (18)"
                    },
                    {
                        "name": "key_share (51)",
                        "shared_keys": [
                            {
                                "TLS_GREASE (0xdada)": "00"
                            },
                            {
                                "X25519 (29)": "578a9b61934aba2a68a02dc49b0d16e414af4e145d9f85c5ca9f9d6783b0b56b"
                            }
                        ]
                    },
                    {
                        "name": "psk_key_exchange_modes (45)",
                        "PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
                    },
                    {
                        "name": "supported_versions (43)",
                        "versions": [
                            "TLS_GREASE (0x5a5a)",
                            "TLS 1.3",
                            "TLS 1.2",
                            "TLS 1.1",
                            "TLS 1.0"
                        ]
                    },
                    {
                        "name": "compress_certificate (27)",
                        "algorithms": [
                            "zlib (1)"
                        ]
                    },
                    {
                        "name": "TLS_GREASE (0x2a2a)"
                    },
                    {
                        "name": "padding (21)",
                        "padding_data_length": 390
                    }
                ],
                "tls_version_record": "771",
                "tls_version_negotiated": "772",
                "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
                "ja3_hash": "773906b0efdefa24a7f2b8eb6985bf37",
                "ja4": "t13d2014h2_a09f3c656075_f62623592221",
                "peetprint": "GREASE-772-771-770-769|2-1.1|GREASE-29-23-24-25|1027-2052-1025-1283-515-2053-2053-1281-2054-1537-513|1|1|GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|0-10-11-13-16-18-21-23-27-43-45-5-51-65281-GREASE-GREASE",
                "peetprint_hash": "b2bafdc69377086c3416be278fd21121",
                "client_random": "591179e6720f34cc024ab3dfe769e11508534bccee62fd09872986f87bdd19af",
                "session_id": "8e09797e6c51004f24086b70be7caa7d791e962ae8489d820128c57f986d1aec"
            },
            "http2": {
                "akamai_fingerprint": "2:0,4:4194304,3:100|10485760|0|m,s,p,a",
                "akamai_fingerprint_hash": "9ae8bfc525dbc7024da8568c424524a3",
                "sent_frames": [
                    {
                        "frame_type": "SETTINGS",
                        "length": 18,
                        "settings": [
                            "ENABLE_PUSH = 0",
                            "INITIAL_WINDOW_SIZE = 4194304",
                            "MAX_CONCURRENT_STREAMS = 100"
                        ]
                    },
                    {
                        "frame_type": "WINDOW_UPDATE",
                        "length": 4,
                        "increment": 10485760
                    },
                    {
                        "frame_type": "HEADERS",
                        "stream_id": 1,
                        "length": 252,
                        "headers": [
                            ":method: GET",
                            ":scheme: https",
                            ":path: /api/all",
                            ":authority: tls.peet.ws",
                            "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "sec-fetch-site: none",
                            "accept-encoding: gzip, deflate, br",
                            "sec-fetch-mode: navigate",
                            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                            "accept-language: zh-CN,zh-Hans;q=0.9",
                            "sec-fetch-dest: document"
                        ],
                        "flags": [
                            "EndStream (0x1)",
                            "EndHeaders (0x4)",
                            "Priority (0x20)"
                        ],
                        "priority": {
                            "weight": 255,
                            "depends_on": 0,
                            "exclusive": 0
                        }
                    }
                ]
            },
            "tcpip": {
                "ip": {},
                "tcp": {}
            }
        }
    )
    rsp2 = await downloader2.fetch(Request(url="https://tls.peet.ws/api/all"))
    print()


if __name__ == '__main__':
    asyncio.run(main())
