#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import signal
import sys
import threading
import time
import urllib.parse
import uuid
from typing import Any, Dict, Optional

import requests


DEFAULT_CONFIG = {
    "Interval": 60,
    "AccessKeyId": "yourAccessKeyId",
    "AccessKeySecret": "yourAccessKeySecret",
    "DomainName": "example.com",
    "SubDomainName": "home",
    "Type": "A",
    "Line": "default",
    "TTL": 600,
    "GetIpUrls": [
        "https://api.ipify.org",
        "https://ident.me",
        "https://checkip.amazonaws.com"
    ],
    "LogFile": "aliddns.log",
    "PidFile": "aliddns.pid"
}


class PidFile:
    def __init__(self, pid_file: str):
        self.pid_file = pid_file

    def exists(self) -> bool:
        if not os.path.exists(self.pid_file):
            return False
        try:
            with open(self.pid_file, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except Exception:
            return False

    def read_pid(self) -> Optional[int]:
        try:
            with open(self.pid_file, "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except Exception:
            return None

    def write(self):
        with open(self.pid_file, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))

    def remove(self):
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
        except Exception:
            pass


class AliDDNS:
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self.load_config(config_file)
        self.validate_config()

        self.endpoint = "https://alidns.aliyuncs.com"
        self.stop_event = threading.Event()
        self.current_ip = None

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "AliDDNS/2.0"
        })

        self.logger = self.setup_logger(self.config.get("LogFile", "aliddns.log"))

    def setup_logger(self, log_file: str) -> logging.Logger:
        logger = logging.getLogger("AliDDNS")
        logger.setLevel(logging.INFO)

        if logger.handlers:
            return logger

        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s"
        )

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def load_config(self, config_file: str) -> Dict[str, Any]:
        with open(config_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def validate_config(self):
        required_fields = [
            "AccessKeyId",
            "AccessKeySecret",
            "DomainName",
            "SubDomainName",
            "Type",
            "Interval"
        ]
        for field in required_fields:
            if field not in self.config or self.config[field] in ("", None):
                raise ValueError(f"配置项缺失: {field}")

        self.config["Interval"] = int(self.config.get("Interval", 60))
        self.config["TTL"] = int(self.config.get("TTL", 600))

        if self.config["Interval"] <= 0:
            raise ValueError("Interval 必须大于 0")

        if self.config["TTL"] <= 0:
            raise ValueError("TTL 必须大于 0")

        if self.config["Type"] not in ("A", "AAAA"):
            raise ValueError("Type 仅支持 A 或 AAAA")

        if not isinstance(self.config.get("GetIpUrls", []), list):
            raise ValueError("GetIpUrls 必须是列表")

    def percent_encode(self, value: Any) -> str:
        result = urllib.parse.quote(str(value), safe="")
        result = result.replace("+", "%20")
        result = result.replace("*", "%2A")
        result = result.replace("%7E", "~")
        return result

    def sign_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        signed = dict(params)
        signed.update({
            "Format": "JSON",
            "Version": "2015-01-09",
            "AccessKeyId": self.config["AccessKeyId"],
            "SignatureMethod": "HMAC-SHA1",
            "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "SignatureVersion": "1.0",
            "SignatureNonce": str(uuid.uuid4())
        })

        sorted_params = sorted((k, str(v)) for k, v in signed.items())
        canonicalized_query_string = "&".join(
            f"{self.percent_encode(k)}={self.percent_encode(v)}"
            for k, v in sorted_params
        )

        string_to_sign = "GET&%2F&" + self.percent_encode(canonicalized_query_string)
        key = (self.config["AccessKeySecret"] + "&").encode("utf-8")
        message = string_to_sign.encode("utf-8")

        signature = base64.b64encode(
            hmac.new(key, message, hashlib.sha1).digest()
        ).decode("utf-8")

        signed["Signature"] = signature
        return signed

    def api_request(self, action: str, extra_params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        params = {"Action": action}
        if extra_params:
            params.update(extra_params)

        try:
            signed_params = self.sign_request(params)
            response = self.session.get(self.endpoint, params=signed_params, timeout=15)
            response.raise_for_status()

            result = response.json()
            if "Code" in result:
                self.logger.error("API错误 %s: %s - %s", action, result.get("Code"), result.get("Message", ""))
                return None
            return result

        except requests.RequestException as e:
            self.logger.error("网络请求失败 %s: %s", action, e)
            return None
        except json.JSONDecodeError as e:
            self.logger.error("API响应不是合法JSON %s: %s", action, e)
            return None
        except Exception as e:
            self.logger.exception("未知错误 %s: %s", action, e)
            return None

    def get_public_ip(self) -> Optional[str]:
        ip_type = self.config["Type"]
        urls = self.config.get("GetIpUrls", [])

        for url in urls:
            try:
                response = self.session.get(url, timeout=8)
                response.raise_for_status()
                ip = response.text.strip()
                if self.is_valid_ip(ip, ip_type):
                    return ip
                self.logger.warning("IP来源返回无效%s地址: %s -> %s", ip_type, url, ip)
            except requests.RequestException as e:
                self.logger.warning("获取公网IP失败: %s (%s)", url, e)
            except Exception as e:
                self.logger.warning("处理公网IP响应失败: %s (%s)", url, e)
        return None

    def is_valid_ip(self, ip: str, record_type: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            if record_type == "A":
                return addr.version == 4
            if record_type == "AAAA":
                return addr.version == 6
            return False
        except ValueError:
            return False

    def describe_domain_record(self) -> Optional[Dict[str, Any]]:
        result = self.api_request("DescribeDomainRecords", {
            "DomainName": self.config["DomainName"],
            "RRKeyWord": self.config["SubDomainName"],
            "Type": self.config["Type"],
            "PageSize": 100
        })

        if not result:
            return None

        records = result.get("DomainRecords", {}).get("Record", [])
        for record in records:
            if (
                record.get("RR") == self.config["SubDomainName"]
                and record.get("Type") == self.config["Type"]
            ):
                return record
        return None

    def update_domain_record(self, record_id: str, ip: str) -> bool:
        result = self.api_request("UpdateDomainRecord", {
            "RecordId": record_id,
            "RR": self.config["SubDomainName"],
            "Type": self.config["Type"],
            "Value": ip,
            "TTL": self.config["TTL"],
            "Line": self.config.get("Line", "default")
        })

        if result and "RecordId" in result:
            self.logger.info("更新成功: %s.%s -> %s",
                             self.config["SubDomainName"],
                             self.config["DomainName"],
                             ip)
            return True
        return False

    def add_domain_record(self, ip: str) -> bool:
        result = self.api_request("AddDomainRecord", {
            "DomainName": self.config["DomainName"],
            "RR": self.config["SubDomainName"],
            "Type": self.config["Type"],
            "Value": ip,
            "TTL": self.config["TTL"],
            "Line": self.config.get("Line", "default")
        })

        if result and "RecordId" in result:
            self.logger.info("添加成功: %s.%s -> %s",
                             self.config["SubDomainName"],
                             self.config["DomainName"],
                             ip)
            return True
        return False

    def sync_once(self):
        new_ip = self.get_public_ip()
        if not new_ip:
            self.logger.warning("获取公网IP失败")
            return

        self.logger.info("当前公网IP: %s", new_ip)
        record = self.describe_domain_record()

        if record:
            old_ip = record.get("Value")
            if old_ip == new_ip:
                self.logger.info("DNS记录未变化: %s", new_ip)
                self.current_ip = new_ip
                return

            self.logger.info("检测到IP变化: %s -> %s", old_ip, new_ip)
            if self.update_domain_record(record["RecordId"], new_ip):
                self.current_ip = new_ip
        else:
            self.logger.info("未找到记录，准备新增解析")
            if self.add_domain_record(new_ip):
                self.current_ip = new_ip

    def sleep_with_stop(self, seconds: int):
        end_time = time.time() + seconds
        while time.time() < end_time:
            if self.stop_event.is_set():
                break
            time.sleep(1)

    def run(self):
        self.logger.info("DDNS服务启动")
        self.logger.info("域名: %s.%s",
                         self.config["SubDomainName"],
                         self.config["DomainName"])

        while not self.stop_event.is_set():
            try:
                self.sync_once()
            except Exception as e:
                self.logger.exception("运行异常: %s", e)

            self.logger.info("%s 秒后再次检查", self.config["Interval"])
            self.sleep_with_stop(self.config["Interval"])

        self.logger.info("DDNS服务已停止")

    def stop(self):
        self.stop_event.set()


def create_default_config(config_file="config.json"):
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
    print(f"配置文件已创建: {config_file}")
    print("请修改后重新运行。")


def daemonize():
    if os.name != "posix":
        raise RuntimeError("daemon 模式仅支持类 Unix 系统")

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    os.setsid()

    pid = os.fork()
    if pid > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()

    with open("/dev/null", "r") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open("/dev/null", "a+") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())


def main():
    config_file = "config.json"

    if not os.path.exists(config_file):
        create_default_config(config_file)
        return

    command = sys.argv[1] if len(sys.argv) > 1 else "run"

    with open(config_file, "r", encoding="utf-8") as f:
        config = json.load(f)

    pid_file = config.get("PidFile", "aliddns.pid")
    pid = PidFile(pid_file)

    if command == "status":
        if pid.exists():
            print(f"运行中, PID={pid.read_pid()}")
        else:
            print("未运行")
        return

    if command == "stop":
        if not pid.exists():
            print("服务未运行")
            pid.remove()
            return
        old_pid = pid.read_pid()
        try:
            os.kill(old_pid, signal.SIGTERM)
            print(f"已发送停止信号到 PID={old_pid}")
        except Exception as e:
            print(f"停止失败: {e}")
        return

    if command == "restart":
        if pid.exists():
            old_pid = pid.read_pid()
            try:
                os.kill(old_pid, signal.SIGTERM)
                print(f"已停止旧进程 PID={old_pid}")
                time.sleep(2)
            except Exception as e:
                print(f"停止旧进程失败: {e}")

        command = "start"

    if command == "start":
        if pid.exists():
            print(f"服务已在运行, PID={pid.read_pid()}")
            return
        daemonize()

    elif command == "run":
        if pid.exists():
            print(f"服务已在运行, PID={pid.read_pid()}")
            return

    else:
        print("用法: python aliddns.py [run|start|stop|restart|status]")
        return

    ddns = AliDDNS(config_file)

    def handle_signal(signum, frame):
        ddns.logger.info("收到停止信号: %s", signum)
        ddns.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        pid.write()
        ddns.run()
    finally:
        pid.remove()


if __name__ == "__main__":
    main()

