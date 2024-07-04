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
        # "header_priority": get_header_priority(ja3_config),
        "supported_signature_algorithms": get_supported_signature_algorithms(ja3_config),
        "supported_versions": get_supported_versions(ja3_config),
        "key_share_curves": get_key_share_curves(ja3_config),
        "supported_delegated_credentials_algorithms": get_supported_delegated_credentials_algorithms(ja3_config),
        # "cert_compression_algo": get_cert_compression_algo(ja3_config),
        "additional_decode": None,
        "catch_panics": None,
        "pseudo_header_order": None,
        "cert_compression_algo": "brotli",
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
    return cert_compression_algo


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
                    "weight": priority["weight"],
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
            "ip": "103.151.172.13:24402",
            "http_version": "h2",
            "method": "GET",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "tls": {
                "ciphers": [
                    "TLS_GREASE (0xAAAA)",
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_AES_256_CBC_SHA"
                ],
                "extensions": [
                    {
                        "name": "TLS_GREASE (0x8a8a)"
                    },
                    {
                        "name": "ec_point_formats (11)",
                        "elliptic_curves_point_formats": [
                            "0x00"
                        ]
                    },
                    {
                        "name": "signed_certificate_timestamp (18)"
                    },
                    {
                        "name": "server_name (0)",
                        "server_name": "tls.peet.ws"
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
                        "name": "supported_versions (43)",
                        "versions": [
                            "TLS_GREASE (0x2a2a)",
                            "TLS 1.3",
                            "TLS 1.2"
                        ]
                    },
                    {
                        "name": "extended_master_secret (23)",
                        "master_secret_data": "",
                        "extended_master_secret_data": ""
                    },
                    {
                        "name": "application_layer_protocol_negotiation (16)",
                        "protocols": [
                            "h2",
                            "http/1.1"
                        ]
                    },
                    {
                        "name": "application_settings (17513)",
                        "protocols": [
                            "h2"
                        ]
                    },
                    {
                        "name": "signature_algorithms (13)",
                        "signature_algorithms": [
                            "ecdsa_secp256r1_sha256",
                            "rsa_pss_rsae_sha256",
                            "rsa_pkcs1_sha256",
                            "ecdsa_secp384r1_sha384",
                            "rsa_pss_rsae_sha384",
                            "rsa_pkcs1_sha384",
                            "rsa_pss_rsae_sha512",
                            "rsa_pkcs1_sha512"
                        ]
                    },
                    {
                        "name": "psk_key_exchange_modes (45)",
                        "PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
                    },
                    {
                        "name": "compress_certificate (27)",
                        "algorithms": [
                            "brotli (2)"
                        ]
                    },
                    {
                        "name": "extensionEncryptedClientHello (boringssl) (65037)",
                        "data": "00000100011e002096e5b59a3bafb6f32d55c4ef678bc70628f9e1136bc2d915edc47790adc0967d00b09ccd9869bd5fefde7335c6806cf5b4cebdf42d164a7e0a401cfb2d2df602de8e3cb7e9c5d4d0c73bec2c4c9546919d5e27e4055b1912d5721850b1beba6aa6ef9ba98c7fd625138ad5739a0296fb70e4e3519c01d17021624be79ce7c855a6236fcf7b32c6efacd9b56c405966e02acea694e763d500e2d695cc178efb8f9cddba20cfb3fdf91657491b673faaf277928d7e33a4144f4339ba90c940dbfe67966662851320b64af9bb74bb12bdefebc9"
                    },
                    {
                        "name": "extensionRenegotiationInfo (boringssl) (65281)",
                        "data": "00"
                    },
                    {
                        "name": "supported_groups (10)",
                        "supported_groups": [
                            "TLS_GREASE (0xdada)",
                            "X25519Kyber768 (25497)",
                            "X25519 (29)",
                            "P-256 (23)",
                            "P-384 (24)"
                        ]
                    },
                    {
                        "name": "key_share (51)",
                        "shared_keys": [
                            {
                                "TLS_GREASE (0xdada)": "00"
                            },
                            {
                                "X25519Kyber768 (25497)": "d6db2aac12c5b67ccc4cd9548e6e16ddaa266c5f7f95ea376d0272f6ea9fd012d08443d6f832b4415cce879979006c3943912fd2bae1635cbd24a669000f87780fb97278c0d03b4a10338be7bba420ba52f114d22810de08a62f9118c200740604909d61cba7c6800a6c065c9917c59a4481f75a130788ce0156c58233a541a1f8bc942757a5d9d6805bb9978ea1731541a1c919461cf3ab2e38af4c3960fc4257e4c33247b5c11f310b1a3ab17f4272741c978cd287eeda0528c75cf05890e81145850c5e0a8357bd5250dba4ae761748c3d811cd12ca094c056fb5694ea4228250bb5f27b586b435ef715e7f1b3aae617abe7059b62420c0942aaf65b380d275e40b09fbd339eed4bb4ad16f0c0308ce9b6de2378b9f09248541c02ec3910a7842c3a50abd982c72e899909c2475f57e31f62d6ef7516abca9678ca0b4bb4d106227055a4dd6a862261b0c6b5595e12645adc16077f92a62a76956327e1ea8be8e92964346ad10d1786126496e6678d29b45c17218b815017312cae34973cca12f37767db6b00efcca1851132a63413d317a71ef845b196c5bce336af219c69cf8cea8f252c534a499359a611ac48cb888ef0c0ccab915d219a64b6006a12b9f2973698554762e893900898839eb58b28867bff45395131e7fe99ca43b55494b07ae04c9c1988b6a1396a8c161cb49a63fc34d2958ca1a3668ade4b38784b6cd93768bf736526c02a91968a7a0033f7a3ac7802aaa52c036b69ae166b4f084c01df57300c0b94afac1fdc404de9a17288502e63bc63eaa0ad8e4b47cf477da1755688c1cf6170c1abb98e653954be08d4dd65e01e2471a1cbe339b2dabe034df7044b15a3e5d9b709aa1cfd4bccc11151813b52117719f7a6237abcc6c09a11cccd99916b68ce69559857c461673bb0ac490a20bca0c682026faca39d023ba76534c73235f6a0d31018bc0d315284a4cda69ad4c735a4e57116a9939eaa553fbc906a56947dd18793387bbf7b0bf831b2494e16f706c84e22c884825131770a426c50abb25210db052ac56a6b1964b7909a56c85a45fc31fe35b28a2b127bd709bc8d30e65fa3db73ba89c75b0563341b409583d1b3e177b9704b72b1b4ccb94519619562b29608415017d1326822589acf2b1a86b85858834b4a25a18521568e46b745b08346a6955bd9baff10498667375940b1e48c3ad44f0288e679431986238d257242c5f00953fae836a02b023ed384780435912620bfedb640ee8bd67603c25066184ec39d43a07d99651e258384607925557c9dd309957a51e7dac3ab8dc636486bdcf44c58d9875f86c8c33882ce0ca03fa12867de1778f91b823a5b66c51a6e5b2a2fc640e925090fda60cee08b38284749f0abe6a6c2195e7914f2c3dd61610bf576165d49d54e69423324b6cf47899dcc0603bc3ea48a76eb8cac4757004f674b137a7bcca4d54c07dc29aa4b05c1da0761d40a5a992f5a4313718c34788e127633c94bd3fb76b2857a4c7ab70a77a4bbfab2e151820e8646b69469d8ab5a8f3f04811372b89ca4116b3c8c14599ad9314abda9f481c776252c24bd69b65c030b9a1b701054997039f4638b769121ca80338bf15041e78a2e78500b9d47cbb9aa5a3183f10cb7ecdc64892a11ae62693fa723809b80c7fb680151aeefc488d81f6509b94840bb95a8e81444f1e67a7ec9a46dff960f1cffc49"
                            },
                            {
                                "X25519 (29)": "89e3a3f7878cdf90dd4dca2f7e2323c464918ee0043c7e503b239202ed906e20"
                            }
                        ]
                    },
                    {
                        "name": "session_ticket (35)",
                        "data": ""
                    },
                    {
                        "name": "TLS_GREASE (0x2a2a)"
                    }
                ],
                "tls_version_record": "771",
                "tls_version_negotiated": "772",
                "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,11-18-0-5-43-23-16-17513-13-45-27-65037-65281-10-51-35,25497-29-23-24,0",
                "ja3_hash": "7de8baf04c03e2751f54a16167f3df97",
                "ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
                "peetprint": "GREASE-772-771|2-1.1|GREASE-25497-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
                "peetprint_hash": "b8ce945a4d9a7a9b5b6132e3658fe033",
                "client_random": "db18019e0e0899f61c6a86d8b05025c0d4bccd850d5ea7e0a5731b0facc69e76",
                "session_id": "3e22cb0dd2ed07017584fc4b49f17e87cc55c568a658d21200fdaaeeb5b0db68"
            },
            "http2": {
                "akamai_fingerprint": "1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p",
                "akamai_fingerprint_hash": "90224459f8bf70b7d0a8797eb916dbc9",
                "sent_frames": [
                    {
                        "frame_type": "SETTINGS",
                        "length": 24,
                        "settings": [
                            "HEADER_TABLE_SIZE = 65536",
                            "ENABLE_PUSH = 0",
                            "INITIAL_WINDOW_SIZE = 6291456",
                            "MAX_HEADER_LIST_SIZE = 262144"
                        ]
                    },
                    {
                        "frame_type": "WINDOW_UPDATE",
                        "length": 4,
                        "increment": 15663105
                    },
                    {
                        "frame_type": "HEADERS",
                        "stream_id": 1,
                        "length": 476,
                        "headers": [
                            ":method: GET",
                            ":authority: tls.peet.ws",
                            ":scheme: https",
                            ":path: /api/all",
                            "sec-ch-ua: \\\"Not/A)Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"126\\\", \\\"Google Chrome\\\";v=\\\"126\\",
                            "sec-ch-ua-mobile: ?0",
                            "sec-ch-ua-platform: \\\"macOS\\",
                            "upgrade-insecure-requests: 1",
                            "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                            "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                            "sec-fetch-site: none",
                            "sec-fetch-mode: navigate",
                            "sec-fetch-user: ?1",
                            "sec-fetch-dest: document",
                            "accept-encoding: gzip, deflate, br, zstd",
                            "accept-language: zh-CN,zh;q=0.9,en;q=0.8,km;q=0.7",
                            "priority: u=0, i"
                        ],
                        "flags": [
                            "EndStream (0x1)",
                            "EndHeaders (0x4)",
                            "Priority (0x20)"
                        ],
                        "priority": {
                            "weight": 256,
                            "depends_on": 0,
                            "exclusive": 1
                        }
                    }
                ]
            },
            "tcpip": {
                "cap_length": 66,
                "dst_port": 443,
                "src_port": 24402,
                "ip": {
                    "id": 35416,
                    "ttl": 58,
                    "ip_version": 4,
                    "dst_ip": "205.185.123.167",
                    "src_ip": "103.151.172.13"
                },
                "tcp": {
                    "ack": 3286838980,
                    "checksum": 35762,
                    "seq": 2946331944,
                    "window": 495
                }
            }
        }
    )
    rsp2 = await downloader2.fetch(Request(url="https://tls.peet.ws/api/all"))
    print()


if __name__ == '__main__':
    asyncio.run(main())
