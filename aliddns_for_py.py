import requests
import json
import time
import hashlib
import hmac
import base64
import urllib.parse
import sys
import os

class AliDDNS:
    def __init__(self, config_file="config.json"):
        self.config = self.load_config(config_file)
        self.current_ip = None
        self.running = True
        self.endpoint = "https://alidns.aliyuncs.com"
    
    def load_config(self, config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def get_public_ip(self):
        urls = self.config.get("GetIpUrls", [
            "https://api.ipify.org", 
            "https://ident.me",
            "https://checkip.amazonaws.com"
        ])
        
        for url in urls:
            try:
                response = requests.get(url, timeout=8)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self.is_valid_ip(ip):
                        return ip
            except:
                continue
        return None
    
    def is_valid_ip(self, ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    
    def sign_request(self, params):
        params.update({
            'Format': 'JSON',
            'Version': '2015-01-09',
            'AccessKeyId': self.config['AccessKeyId'],
            'SignatureMethod': 'HMAC-SHA1',
            'Timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            'SignatureVersion': '1.0',
            'SignatureNonce': str(int(time.time() * 1000))
        })
        
        sorted_params = sorted(params.items())
        canonicalized_query_string = ''
        for key, value in sorted_params:
            canonicalized_query_string += '&' + self.percent_encode(key) + '=' + self.percent_encode(value)
        canonicalized_query_string = canonicalized_query_string[1:]
        
        string_to_sign = 'GET&%2F&' + self.percent_encode(canonicalized_query_string)
        
        key = self.config['AccessKeySecret'] + '&'
        signature = base64.b64encode(
            hmac.new(key.encode('utf-8'), string_to_sign.encode('utf-8'), hashlib.sha1).digest()
        )
        
        params['Signature'] = signature.decode('utf-8')
        return params
    
    def percent_encode(self, string):
        result = urllib.parse.quote(string, safe='')
        result = result.replace('+', '%20')
        result = result.replace('*', '%2A')
        result = result.replace('%7E', '~')
        return result
    
    def api_request(self, action, extra_params=None):
        params = {'Action': action}
        if extra_params:
            params.update(extra_params)
        
        try:
            signed_params = self.sign_request(params)
            response = requests.get(self.endpoint, params=signed_params, timeout=15)
            result = response.json()
            
            if 'Code' in result:
                error_msg = self.get_error_message(result['Code'], result.get('Message', ''))
                print(f"API错误 {action}: {error_msg}")
                return None
            return result
        except requests.exceptions.RequestException as e:
            print(f"网络请求失败: {e}")
            return None
        except json.JSONDecodeError:
            print("API响应格式错误")
            return None
        except Exception as e:
            print(f"未知错误: {e}")
            return None
    
    def get_error_message(self, error_code, message):
        errors = {
            'InvalidAccessKeyId.NotFound': 'AccessKeyId不存在或无效',
            'SignatureDoesNotMatch': '签名验证失败',
            'DomainRecordDuplicate': '解析记录已存在',
            'InvalidDomainName.NoExist': '域名不存在',
            'Forbidden.RAM': '权限不足',
            'Throttling': 'API调用频率限制',
            'InvalidParameter': '参数错误'
        }
        return errors.get(error_code, f'未知错误: {error_code}')
    
    def describe_domain_records(self):
        result = self.api_request('DescribeDomainRecords', {
            'DomainName': self.config['DomainName'],
            'RRKeyWord': self.config['SubDomainName'],
            'Type': self.config['Type']
        })
        
        if result and 'DomainRecords' in result:
            records = result['DomainRecords'].get('Record', [])
            for record in records:
                if record.get('RR') == self.config['SubDomainName']:
                    return record
        return None
    
    def update_domain_record(self, record_id, ip):
        result = self.api_request('UpdateDomainRecord', {
            'RecordId': record_id,
            'RR': self.config['SubDomainName'],
            'Type': self.config['Type'],
            'Value': ip,
            'TTL': self.config.get('TTL', '600'),
            'Line': self.config.get('Line', 'default')
        })
        
        if result and 'RecordId' in result:
            print(f"更新成功: {self.config['SubDomainName']}.{self.config['DomainName']} -> {ip}")
            return True
        return False
    
    def add_domain_record(self, ip):
        result = self.api_request('AddDomainRecord', {
            'DomainName': self.config['DomainName'],
            'RR': self.config['SubDomainName'],
            'Type': self.config['Type'],
            'Value': ip,
            'TTL': self.config.get('TTL', '600'),
            'Line': self.config.get('Line', 'default')
        })
        
        if result and 'RecordId' in result:
            print(f"添加成功: {self.config['SubDomainName']}.{self.config['DomainName']} -> {ip}")
            return True
        return False
    
    def run(self):
        print("DDNS服务启动")
        print(f"域名: {self.config['SubDomainName']}.{self.config['DomainName']}")
        print("输入 stop 停止服务")
        print("----------------------------------------")
        
        while self.running:
            try:
                new_ip = self.get_public_ip()
                if not new_ip:
                    print("获取公网IP失败，5分钟后重试")
                    time.sleep(300)
                    continue
                
                print(f"当前公网IP: {new_ip}")
                
                if new_ip != self.current_ip:
                    print("IP变化，更新解析记录")
                    
                    record = self.describe_domain_records()
                    if record:
                        if self.update_domain_record(record['RecordId'], new_ip):
                            self.current_ip = new_ip
                    else:
                        if self.add_domain_record(new_ip):
                            self.current_ip = new_ip
                else:
                    print("IP未变化")
                
                wait_minutes = int(self.config['Interval'])
                print(f"{wait_minutes}分钟后再次检查")
                print("----------------------------------------")
                time.sleep(wait_minutes * 60)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"运行异常: {e}")
                time.sleep(60)
        
        print("服务已停止")

def main():
    if not os.path.exists("config.json"):
        config = {
            "Interval": "1",
            "AccessKeyId": "yourAccessKeyId",
            "AccessKeySecret": "yourAccessKeySecret",
            "DomainName": "ni3 de1 yu4 ming2",
            "SubDomainName": "ni3 de1 zi3 yu4 ming2",
            "Type": "A",
            "Line": "default",
            "TTL": "600",
            "GetIpUrls": [
                "https://api.ipify.org",
                "https://ident.me"
            ]
        }
        with open("config.json", "w", encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        print("配置文件已创建，请检查配置")
        return
    
    ddns = AliDDNS()
    
    import threading
    def listen_for_stop():
        while True:
            if input().strip().lower() == 'stop':
                ddns.running = False
                break
    
    stop_thread = threading.Thread(target=listen_for_stop, daemon=True)
    stop_thread.start()
    
    ddns.run()

if __name__ == "__main__":
    main()
