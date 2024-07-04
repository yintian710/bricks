# -*- coding: utf-8 -*-
# @Time    : 2023-12-10 22:07
# @Author  : Kem
# @Desc    :

from __future__ import absolute_import

import copy
import urllib.parse
import warnings
from typing import Union

from bricks.downloader import AbstractDownloader
from bricks.lib.cookies import Cookies
from bricks.lib.request import Request
from bricks.lib.response import Response
from bricks.utils import pandora

warnings.filterwarnings("ignore")
pandora.require("requests-go")

import requests_go  # noqa: E402
from requests_go.tls_config import TLSConfig, to_tls_config  # noqa: E402


class Downloader(AbstractDownloader):
    """
    对 requests-go 进行的一层包装, 支持手动设置 tls
    兼容 Windows / Mac / Linux


    """

    def __init__(self, tls_config: [dict, TLSConfig] = None) -> None:
        self.tls_config = tls_config

    def fetch(self, request: Union[Request, dict]) -> Response:
        """
        真使用 requests 发送请求并获取响应

        :param request:
        :return: `Response`

        """

        res = Response.make_response(request=request)
        options = {
            'method': request.method.upper(),
            'headers': request.headers,
            'cookies': request.cookies,
            "data": self.parse_data(request)['data'],
            'files': request.options.get('files'),
            'auth': request.options.get('auth'),
            'timeout': 5 if request.timeout is ... else request.timeout,
            'allow_redirects': False,
            'proxies': request.proxies and {"http": request.proxies, "https": request.proxies},  # noqa
            'verify': request.options.get("verify", False),
        }

        tls_config = request.options.get("tls_config")
        if not tls_config:
            tls_config = self.tls_config
        # tls_config = self.fmt_tls_config(tls_config)

        tls_config and options.update(tls_config=tls_config)
        next_url = request.real_url
        _redirect_count = 0
        if request.use_session:
            session = request.get_options("$session") or self.get_session()
        else:
            session = requests_go

        while True:
            assert _redirect_count < 999, "已经超过最大重定向次数: 999"
            response = session.request(**{**options, "url": next_url})
            last_url, next_url = next_url, response.headers.get('location') or response.headers.get('Location')
            if request.allow_redirects and next_url:
                next_url = urllib.parse.urljoin(response.url, next_url)
                _redirect_count += 1
                res.history.append(
                    Response(
                        content=response.content,
                        headers=response.headers,
                        cookies=Cookies.by_jar(response.cookies),
                        url=response.url,
                        status_code=response.status_code,
                        request=Request(
                            url=last_url,
                            method=request.method,
                            headers=copy.deepcopy(options.get('headers'))
                        )
                    )
                )
                request.options.get('$referer', False) and options['headers'].update(Referer=response.url)

            else:
                res.content = response.content
                res.headers = response.headers
                res.cookies = Cookies.by_jar(response.cookies)
                res.url = response.url
                res.status_code = response.status_code
                res.request = request

                return res

    def make_session(self):
        return requests_go.Session()

    @classmethod
    def fmt_tls_config(cls, tls_config: [dict, TLSConfig] = None) -> TLSConfig:
        """
        将 tls_config 直接转为 TLSConfig, 因为有时候直接传 dict 给 request_go 有问题
        :param tls_config:
        :return:
        """
        if not tls_config:
            return tls_config

        if isinstance(tls_config, dict):
            tls_config = to_tls_config(tls_config)
        assert isinstance(tls_config, TLSConfig), f'tls_config 需要为 dict 或者 TLSConfig'
        return tls_config


def to_tls_config(config: dict):
    tls_config = TLSConfig()._fromJSON({
        "ja3": get_ja3_string(config),
        "headers_order": get_header_order(config),
        "force_http1": get_force_http1(config),
        "pseudo_header_order": get_pseudo_header_order(config),
        "tls_extensions": {
            "supported_signature_algorithms": get_supported_signature_algorithms(config),
            "cert_compression_algo": get_cert_compression_algo(config),
            "record_size_limit": get_record_size_limit(config),
            "supported_delegated_credentials_algorithms": get_supported_delegated_credentials_algorithms(config),
            "supported_versions": get_supported_versions(config),
            "psk_key_exchange_modes": get_psk_key_exchange_modes(config),
            "signature_algorithms_cert": get_signature_algorithms_cert(config),
            "key_share_curves": get_key_share_curves(config),
            "not_used_grease": get_not_used_grease(config),
        },
        "http2_settings": {
            "settings": get_h2_settings(config),
            "settings_order": get_h2_settings_order(config),
            "connection_flow": get_connection_flow(config),
            "header_priority": get_header_priority(config),
            "priority_frames": get_priority_frames(config),
        }
    })

    return tls_config


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


if __name__ == '__main__':
    downloader = Downloader(tls_config=to_tls_config({
        "ip": "218.250.111.85:10349",
        "http_version": "h2",
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "tls": {
            "ciphers": [
                "TLS_GREASE (0x2A2A)",
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
                    "name": "TLS_GREASE (0x3a3a)"
                },
                {
                    "name": "extensionRenegotiationInfo (boringssl) (65281)",
                    "data": "00"
                },
                {
                    "name": "session_ticket (35)",
                    "data": ""
                },
                {
                    "name": "key_share (51)",
                    "shared_keys": [
                        {
                            "TLS_GREASE (0x5a5a)": "00"
                        },
                        {
                            "X25519Kyber768 (25497)": "2b8d419c0f783e1d45ae335b18efd91945098d57e6363ca478eb1ef9dd015d6b95d86b34257ced928066607438d7a4ca05c6bf939d927106fbd694449910aaa86451bb01c226682a60499b9456679a6cb7847820d08f9c15084dc0ad7453556f415eeb0902b391c7314064df981b7a1301e438a2f0f59fba3b86b0417b879b2f668896ed376c28c69cf8587d4e796268a3ca39f33f83f2056da404c24a1988c3a25c05177af4a3c9047560511f2438a72c187ce71859b1aa1dadf54ba0c419dc152576b432a309a7daab653ca4a4243a12306ac1ea0b40f0638840bc104668c0644c979a0a5d8a0b7bd2479eb834cee920bc5fa3baa49a8853063bd36b73e5124a72e7663c712c734a2c6185b146211a89985082a8c6c82562e02b09aa3b8417242eedeb4aa9c11766162f40244d57b6ae2c642a2ca45eb2369ce0723adb2a2b71448a057c9587c2affdd35ca9811333dc9ce1c5028a972a3911c0394c347c8007d937c2e6352d107bb0affc245e7baeeef29f3b223ba7534c3b8483ea831cc173aa8dc5c1dbeb6627c22887ca8357b85e72fa0b7e057fac3b4787e0c294dc0421e5a63089877605a784c10b5c951475c7541a10417be417731700479c912de67761d00781e6b0c5e06912f33078048f5c557754643b61c3b269060ab914c14a89667ffb3b9e33689c65c087874fe0ba4f2646ab21bc044a4c795ae83ca7f0b85021568fe35ba5a3c128aca520f94bf5a0502267c210d646d2537ae157367f18b16593778718260970642391c1f56c9c375b9d9f26a3f917a8e6751f0cf88ae2375996e8765a941e78a73b64205090e12cfecb86324a4f32e44fafc14709d3562c578de165807e24b7ee8bbb0cc41f9f06b5a5f86284638be26ab9b2a608446bafb7b4324e4acea85731ed183ccbb7185d88ab8f6508b1cbb821ca1f7257869010a3bd2161ac94678b9192173526d2986a226312e4fa4356f3841bf3093953a31d240194769ff695b57df673070b9b20e7c9803c286c0937db0c743ffc6eb1bb17918865cce9c8914812bb6c438d16b58ce433704810e14b6638ebc5e204ab8df1b88d17574fe67d1f8a4e391b51999a339ebb7a31254649ac67f4d176d6196483a85100f16949228b8ea17f6bb84b8e597f3dca8eadca4e1a793f128171485cb3d97a34380c1291f7884a0a740fdc0801ac6280474b3126b14eca316265ad33ca2eb7d67d361184a6ab59a3b06905e0784d30631e06b9bb49147c3953b4811fd2562f7f4c60306436d915981a97bb6490cf4d49bc0271c9171a673665a5bb127ac3c1723fdc98cd0bacecb27503653a2b4cb07ce6c04b2c6ce4f5ae923aa707e5cda8e2a2d5487bf60105f2393a9b66c32d746637fc3ce95aa6464abd2ca59b62178cdef7b67d1c9d0ba667964226ddb171d2f642dd3046def5c749076bcea2a04bb70ea2f222d1a7464cdbc42d63073f130bd82a5d52264a28c4354349aeb2aa6eca3c1659dc86f4ba9859d59de30c82cf2253c6d1c6c3d03fad1a757e7a259f79cdfc286c7a96aa4c8b7ec14128db27407010a8a61ac5d05c65f50237b8e965ced86eed2071c1b18f18e82be0436978d99fb7661af122a62b72c0568c64441174435a7a05f01ab22c1a243499bcbb683416618a060baa226487da66392aa780808bd49072265ec284828a0f1060eb2638a789a9738c47f93fe58d39fbfb80"
                        },
                        {
                            "X25519 (29)": "5a289ff97d652b948a0a10562dbaff4a8cedc5d85e5f08fbd5eef513afe7ba32"
                        }
                    ]
                },
                {
                    "name": "application_settings (17513)",
                    "protocols": [
                        "h2"
                    ]
                },
                {
                    "name": "extensionEncryptedClientHello (boringssl) (65037)",
                    "data": "0000010001500020547d0701b6ee3df30eceb796147e74a478eb04236d11e5ccd0ca153e7524303d00902e2b35546b82830b8312b57f976f6607e993f67b510947e33ea90bd60b4c51716adb19673fc113df722fee574f052194f1cd8277ab2bf7bee245064c7007e74a99d7a74e467df8da6af265685436cfcbbeb6e79763868b69c719d4bf62a8cd2cc2e98db02e734b72a914c4449ef2c41abb416769ecc88cdf5ec32c0b30a2bdd4b852fb2432d65e0e71541ce85c791753"
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
                    "name": "signed_certificate_timestamp (18)"
                },
                {
                    "name": "server_name (0)",
                    "server_name": "tls.peet.ws"
                },
                {
                    "name": "supported_groups (10)",
                    "supported_groups": [
                        "TLS_GREASE (0x5a5a)",
                        "X25519Kyber768 (25497)",
                        "X25519 (29)",
                        "P-256 (23)",
                        "P-384 (24)"
                    ]
                },
                {
                    "name": "compress_certificate (27)",
                    "algorithms": [
                        "brotli (2)"
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
                    "name": "supported_versions (43)",
                    "versions": [
                        "TLS_GREASE (0xaaaa)",
                        "TLS 1.3",
                        "TLS 1.2"
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
                    "name": "TLS_GREASE (0x8a8a)"
                }
            ],
            "tls_version_record": "771",
            "tls_version_negotiated": "772",
            "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-35-51-17513-65037-13-45-18-0-10-27-23-16-11-43-5,25497-29-23-24,0",
            "ja3_hash": "82f740fab58d05ca0dfa38d70f433f7d",
            "ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
            "peetprint": "GREASE-772-771|2-1.1|GREASE-25497-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17513-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
            "peetprint_hash": "b8ce945a4d9a7a9b5b6132e3658fe033",
            "client_random": "e815a669407a5153eb0cbb620a27e36406722c012851b004d7c6ba94455ac4a1",
            "session_id": "7d6e6f90ffe736744ab2c26c424c9d24c0dd5dd3ed1b699a105ba2c762a827ae"
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
                    "length": 473,
                    "headers": [
                        ":method: GET",
                        ":authority: tls.peet.ws",
                        ":scheme: https",
                        ":path: /api/all",
                        "sec-ch-ua: \\\"Not/A)Brand\\\";v=\\\"8\\\", \\\"Chromium\\\";v=\\\"126\\\", \\\"Google Chrome\\\";v=\\\"126\\",
                        "sec-ch-ua-mobile: ?0",
                        "sec-ch-ua-platform: \\\"Windows\\",
                        "upgrade-insecure-requests: 1",
                        "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
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
            "src_port": 10349,
            "ip": {
                "id": 31097,
                "ttl": 55,
                "ip_version": 4,
                "dst_ip": "205.185.123.167",
                "src_ip": "218.250.111.85"
            },
            "tcp": {
                "ack": 3264529410,
                "checksum": 62895,
                "seq": 2320068117,
                "window": 73
            }
        }
    }))
    resp = downloader.fetch({"url": "https://tls.peet.ws/api/all", "proxies": "http://127.0.0.1:7890"})
    print(resp)
