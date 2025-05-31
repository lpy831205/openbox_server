import base64
import hashlib
import json
import logging
import os
import re
import secrets
import time
import ipaddress
import shutil
from datetime import datetime, timedelta
from difflib import get_close_matches
from functools import wraps
from collections import defaultdict, deque

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
# 添加passlib用于安全密码哈希
from passlib.hash import argon2

# 全局缓存变量
QUERY_RECORDS_CACHE = {
    "data": [],
    "last_modified": 0
}

# 加载查询记录，使用缓存提高效率
def load_query_records():
    global QUERY_RECORDS_CACHE
    
    if not os.path.exists(QUERY_RECORDS_FILE):
        return []
        
    # 获取文件最后修改时间
    file_mtime = os.path.getmtime(QUERY_RECORDS_FILE)
    
    # 如果缓存有效，直接返回缓存数据
    if QUERY_RECORDS_CACHE["last_modified"] == file_mtime and QUERY_RECORDS_CACHE["data"]:
        return QUERY_RECORDS_CACHE["data"]
    
    # 缓存无效，重新加载数据
    records = []
    try:
        with open(QUERY_RECORDS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    continue
                    
        # 更新缓存
        QUERY_RECORDS_CACHE["data"] = records
        QUERY_RECORDS_CACHE["last_modified"] = file_mtime
        
        logging.info(f"查询记录缓存已更新，加载了 {len(records)} 条记录")
        return records
    except Exception as e:
        logging.error(f"加载查询记录失败: {str(e)}")
        return []

# 初始化Flask应用
app = Flask(__name__)
# 更安全的CORS配置
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5173", "https://ldfmidleschool.com"],  # 限制允许的源
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Encrypted-Key", "X-Signature", 
                         "X-Nonce", "X-Timestamp", "X-Client-IP"],
        "expose_headers": ["Content-Type", "Content-Length"],
        "supports_credentials": True,
        "max_age": 600  # 10分钟的预检请求缓存
    }
})

# 配置常量
RSA_KEY_SIZE = 3072
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
AES_KEY_SIZE = 32  # 256-bit
AES_IV_SIZE = 16  # 128-bit
# 添加密钥加密密码环境变量名
KEY_PASSWORD_ENV = "RSA_KEY_PASSWORD"

# 安全配置常量
MAX_LOGIN_ATTEMPTS = 5  # 最大登录尝试次数
LOCKOUT_DURATION = 900  # 锁定时间（秒）
RATE_LIMIT_REQUESTS = 100  # 每分钟最大请求数
RATE_LIMIT_WINDOW = 60  # 速率限制时间窗口（秒）
MAX_REQUEST_SIZE = 1024 * 1024  # 最大请求大小（1MB）
SESSION_TIMEOUT = 3600  # 会话超时时间（秒）
DEVICE_CODE_REGEX = re.compile(r'^[0-9a-fA-F]{128}$')  # SHA3-512 (128 hex chars)
LOG_FILE = "server.log"
QUERY_RECORDS_FILE = "query_records.json"
USERS_FILE = "users.json"
BLACKLIST_IPS_FILE = "blacklist_ips.json"
# 新增令牌存储文件
TOKENS_FILE = "tokens.json"
FIELD_MAPPING = {
    "_widget_1676622873142": "学期",
    "_widget_1676628877052": "报名时间",
    "_widget_1676627525406": "身份证号",
    "_widget_1676627525409": "姓名",
    "_widget_1676627525413": "班级",
    "_widget_1676622873132": "年级",
    "_widget_1676622873131": "课程",
    "_widget_1676622873128": "课程类型",
    "_widget_1676637687681": "任课教师",
    "_widget_1676622873135": "上课时间",
    "_widget_1676622873134": "报名人数上限",
    "_widget_1676627525424": "已报名人数",
    "_widget_1676622873137": "备注",
    "_widget_1676631087389": "确认信息"
}
FIELD_MAPPING_INV = {v: k for k, v in FIELD_MAPPING.items()}
FUZZY_THRESHOLD = 0.4

# 初始化日志
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,  # 修改为DEBUG级别，以便查看更详细的调试信息
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 添加终端日志输出
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # 终端输出也设置为DEBUG级别
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logging.getLogger().addHandler(console_handler)

# 全局密钥变量
private_key = None
public_key = None

# Nonce缓存 (简单的内存实现，用于防重放)
# 结构: {nonce_value: timestamp_ms}
NONCE_CACHE = {}
NONCE_CACHE_EXPIRY_MS = 5 * 60 * 1000  # 5分钟Nonce有效期

# Token存储 (文件系统实现，替代内存存储)
# 结构: {token: {"account": str, "role": str, "expiry": datetime}}
TOKENS = {}
TOKEN_EXPIRY_MINUTES = 60  # Token有效期60分钟
SUPERADMIN_ROLE = 'superadmin'
ADMIN_ROLE = 'admin'
USER_ROLE = 'user'

# 安全监控全局变量
login_attempts = defaultdict(list)  # IP地址 -> 登录尝试时间列表
rate_limit_tracker = defaultdict(deque)  # IP地址 -> 请求时间队列
blocked_ips = {}  # IP地址 -> 解封时间
suspicious_activities = []  # 可疑活动记录
blacklist_ips = set()  # 黑名单IP地址集合

# 添加风控计数器
SECURITY_VIOLATION_COUNTERS = {
    "ip": {},  # 格式: {ip: {"count": 0, "last_violation": timestamp}}
    "device_code": {}  # 格式: {device_code: {"count": 0, "last_violation": timestamp}}
}

# 风控阈值
MAX_SECURITY_VIOLATIONS_IP = 2  # IP安全违规次数阈值
MAX_INVITE_CODE_FAILURES = 3  # 邀请码错误次数阈值
VIOLATION_RESET_TIME = 3600  # 违规计数器重置时间（秒）

def is_valid_ip(ip_str):
    """验证IP地址格式是否有效
    
    Args:
        ip_str: IP地址字符串
        
    Returns:
        bool: IP地址是否有效
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def get_client_ip():
    """获取客户端真实IP地址
    
    尝试从各种HTTP头中获取真实的客户端IP地址
    
    Returns:
        str: 客户端IP地址
    """
    # 首先检查X-Client-IP头（前端通过ipify API获取的公网IP）
    x_client_ip = request.headers.get('X-Client-IP')
    if x_client_ip and is_valid_ip(x_client_ip):
        return x_client_ip
    
    # 然后检查X-Forwarded-For头
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # 取列表中的第一个IP地址，即最初的客户端IP
        ip = x_forwarded_for.split(',')[0].strip()
        if is_valid_ip(ip):
            return ip
    
    # 然后检查X-Real-IP头
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip and is_valid_ip(x_real_ip):
        return x_real_ip
    
    # 最后使用请求的远程地址
    if request.remote_addr and is_valid_ip(request.remote_addr):
        return request.remote_addr
    
    # 如果都无法获取有效IP，返回未知
    return '0.0.0.0'

def check_rate_limit(client_ip):
    """检查客户端IP的请求速率限制
    
    Args:
        client_ip: 客户端IP地址
        
    Returns:
        bool: 是否超过速率限制
    """
    # 如果IP在黑名单中，直接拒绝
    if client_ip in blacklist_ips:
        logging.warning(f"拒绝来自黑名单IP的请求: {client_ip}")
        return True
        
    current_time = time.time()
    
    # 清理过期的请求记录
    while (rate_limit_tracker[client_ip] and 
           current_time - rate_limit_tracker[client_ip][0] > RATE_LIMIT_WINDOW):
        rate_limit_tracker[client_ip].popleft()
    
    # 检查是否超过限制
    if len(rate_limit_tracker[client_ip]) >= RATE_LIMIT_REQUESTS:
        logging.warning(f"IP {client_ip} 请求频率超限: {len(rate_limit_tracker[client_ip])}次/{RATE_LIMIT_WINDOW}秒")
        return True
    
    # 记录当前请求
    rate_limit_tracker[client_ip].append(current_time)
    return False

def check_login_attempts(client_ip):
    """检查登录尝试次数是否超限
    
    Args:
        client_ip: 客户端IP地址
        
    Returns:
        bool: 是否被锁定
    """
    current_time = time.time()
    
    # 检查是否在锁定期内
    if client_ip in blocked_ips:
        if current_time < blocked_ips[client_ip]:
            return True
        else:
            # 锁定期已过，移除锁定
            del blocked_ips[client_ip]
            login_attempts[client_ip] = []
    
    # 清理过期的登录尝试记录
    login_attempts[client_ip] = [
        attempt_time for attempt_time in login_attempts[client_ip]
        if current_time - attempt_time < LOCKOUT_DURATION
    ]
    
    return False

def record_failed_login(client_ip):
    """记录失败的登录尝试
    
    Args:
        client_ip: 客户端IP地址
    """
    current_time = time.time()
    login_attempts[client_ip].append(current_time)
    
    # 检查是否需要锁定
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        blocked_ips[client_ip] = current_time + LOCKOUT_DURATION
        logging.warning(f"IP {client_ip} 已被锁定 {LOCKOUT_DURATION} 秒，原因：登录尝试次数过多")

def log_suspicious_activity(client_ip, activity_type, details):
    """记录可疑活动
    
    Args:
        client_ip: 客户端IP地址
        activity_type: 活动类型
        details: 详细信息
    """
    activity = {
        'timestamp': datetime.now().isoformat(),
        'ip': client_ip,
        'type': activity_type,
        'details': details
    }
    suspicious_activities.append(activity)
    
    # 保持最近1000条记录
    if len(suspicious_activities) > 1000:
        suspicious_activities.pop(0)
    
    logging.warning(f"可疑活动检测 - IP: {client_ip}, 类型: {activity_type}, 详情: {details}")

def record_security_violation(ip, violation_type, device_code=None):
    """记录安全违规
    
    Args:
        ip: 客户端IP
        violation_type: 违规类型
        device_code: 设备码（可选）
    """
    current_time = time.time()
    
    # 记录IP违规
    if violation_type in ["signature_mismatch", "timestamp_invalid", "nonce_reuse"]:
        if ip not in SECURITY_VIOLATION_COUNTERS["ip"]:
            SECURITY_VIOLATION_COUNTERS["ip"][ip] = {"count": 0, "last_violation": 0}
            
        # 检查是否需要重置计数器
        if current_time - SECURITY_VIOLATION_COUNTERS["ip"][ip]["last_violation"] > VIOLATION_RESET_TIME:
            SECURITY_VIOLATION_COUNTERS["ip"][ip]["count"] = 0
            
        # 增加计数
        SECURITY_VIOLATION_COUNTERS["ip"][ip]["count"] += 1
        SECURITY_VIOLATION_COUNTERS["ip"][ip]["last_violation"] = current_time
        
        # 检查是否达到阈值
        if SECURITY_VIOLATION_COUNTERS["ip"][ip]["count"] >= MAX_SECURITY_VIOLATIONS_IP:
            # 将IP加入黑名单
            blacklist_ips.add(ip)
            save_blacklist_ips()
            logging.warning(f"IP {ip} 已被加入黑名单，原因：安全违规次数达到阈值 ({MAX_SECURITY_VIOLATIONS_IP})")
            
    # 记录设备码违规（邀请码错误）
    if violation_type == "invite_code_failure" and device_code:
        if device_code not in SECURITY_VIOLATION_COUNTERS["device_code"]:
            SECURITY_VIOLATION_COUNTERS["device_code"][device_code] = {"count": 0, "last_violation": 0}
            
        # 检查是否需要重置计数器
        if current_time - SECURITY_VIOLATION_COUNTERS["device_code"][device_code]["last_violation"] > VIOLATION_RESET_TIME:
            SECURITY_VIOLATION_COUNTERS["device_code"][device_code]["count"] = 0
            
        # 增加计数
        SECURITY_VIOLATION_COUNTERS["device_code"][device_code]["count"] += 1
        SECURITY_VIOLATION_COUNTERS["device_code"][device_code]["last_violation"] = current_time
        
        # 检查是否达到阈值
        if SECURITY_VIOLATION_COUNTERS["device_code"][device_code]["count"] >= MAX_INVITE_CODE_FAILURES:
            # 将设备码加入黑名单
            # 这里需要实现设备码黑名单机制
            # 可以创建一个新的文件来存储被封禁的设备码
            try:
                with open("blocked_device_codes.json", "a+", encoding='utf-8') as f:
                    f.seek(0)
                    try:
                        content = f.read()
                        blocked_devices = json.loads(content) if content else []
                    except json.JSONDecodeError:
                        blocked_devices = []
                    
                    if device_code not in blocked_devices:
                        blocked_devices.append(device_code)
                        
                    f.seek(0)
                    f.truncate()
                    json.dump(blocked_devices, f)
                    
                logging.warning(f"设备码 {device_code} 已被封禁，原因：邀请码错误次数达到阈值 ({MAX_INVITE_CODE_FAILURES})")
            except Exception as e:
                logging.error(f"封禁设备码失败: {str(e)}")

def validate_request_data():
    """验证请求数据的安全性
    
    检查请求大小、内容类型等安全问题
    
    Returns:
        bool: 请求是否安全
    """
    # 检查请求大小
    content_length = request.content_length
    if content_length and content_length > MAX_REQUEST_SIZE:
        client_ip = get_client_ip()
        log_suspicious_activity(client_ip, 'OVERSIZED_REQUEST', 
                               f"请求大小: {content_length} bytes, 超过限制: {MAX_REQUEST_SIZE} bytes")
        return False
    
    # 检查内容类型
    if request.method in ['POST', 'PUT'] and request.content_type:
        if not request.content_type.startswith(('application/json', 'multipart/form-data', 'application/x-www-form-urlencoded')):
            client_ip = get_client_ip()
            log_suspicious_activity(client_ip, 'INVALID_CONTENT_TYPE', 
                                   f"不支持的内容类型: {request.content_type}")
            return False
    
    # 检查路径注入
    path = request.path
    if '../' in path or '%2e%2e' in path.lower() or '\\' in path:
        client_ip = get_client_ip()
        log_suspicious_activity(client_ip, 'PATH_INJECTION', 
                               f"可疑路径: {path}")
        return False
    
    # 检查查询参数
    for key, value in request.args.items():
        # 检查SQL注入
        if isinstance(value, str) and any(sql_pattern in value.lower() for sql_pattern in 
                                         ['select ', 'union ', 'insert ', 'delete ', 'update ', 'drop ', 
                                          'exec ', '--', '/*', '*/', '@@', '@variable', 'waitfor']):
            client_ip = get_client_ip()
            log_suspicious_activity(client_ip, 'SQL_INJECTION', 
                                   f"可疑查询参数: {key}={value}")
            return False
        
        # 检查XSS
        if isinstance(value, str) and any(xss_pattern in value.lower() for xss_pattern in 
                                         ['<script>', 'javascript:', 'onerror=', 'onload=', 'eval(', 
                                          'document.cookie', 'alert(', 'onclick=']):
            client_ip = get_client_ip()
            log_suspicious_activity(client_ip, 'XSS_ATTEMPT', 
                                   f"可疑XSS参数: {key}={value}")
            return False
    
    return True

def parse_class_query(class_query_str: str) -> str:
    """解析灵活格式的班级查询字符串

    支持多种格式如："2023级10班", "23年10班", "23级10"等
    转换为统一格式如："2310"

    Args:
        class_query_str: 用户输入的班级查询字符串

    Returns:
        str: 解析后的班级字符串
    """
    # 匹配年份部分
    year_match = re.search(r'(\d{2,4})[年级]?', class_query_str)
    # 匹配班级部分
    class_num_match = re.search(r'(\d+)班?', class_query_str)

    if year_match and class_num_match:
        year_str = year_match.group(1)
        class_num_str = class_num_match.group(1)

        # 处理年份
        if len(year_str) == 4 and year_str.startswith("20"):
            parsed_year = year_str[2:]
        elif len(year_str) == 2:
            parsed_year = year_str
        else:
            # 非常规年份格式，尝试提取所有数字
            numbers = re.findall(r'\d+', class_query_str)
            if numbers:
                return "".join(numbers)
            return class_query_str

        # 班级号补零到两位
        parsed_class_num = class_num_str.zfill(2)
        return f"{parsed_year}{parsed_class_num}"
    else:
        # 无明确年级班级标识，尝试提取所有数字
        numbers = re.findall(r'\d+', class_query_str)
        if numbers:
            return "".join(numbers)
    return class_query_str


def display_records(records: list):
    """格式化并显示报名记录

    Args:
        records: 要显示的记录列表
    """
    if not records:
        print("  无相关报名记录。")
        return

    for i, record in enumerate(records, 1):
        print(f"  记录 {i}:")
        for key, value in record.items():
            display_key = FIELD_MAPPING.get(key, key)
            # 日期时间格式化处理
            if isinstance(value, str) and ('T' in value and 'Z' in value and value.endswith('Z')):
                try:
                    dt_obj = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    value = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    pass  # 保持原始值
            print(f"    {display_key}: {value}")
        print("  ---")


def fuzzy_search(query: str, data: dict):
    """增强版模糊搜索

    Args:
        query: 查询字符串
        data: 要搜索的数据字典

    Returns:
        dict: 匹配的结果字典
    """
    names = list(data.keys())
    initial_matches = get_close_matches(query, names, n=10, cutoff=FUZZY_THRESHOLD)

    # 优先完全匹配查询长度的姓名
    exact_len_matches = [name for name in initial_matches if len(name) == len(query)]
    # 如果没有完全匹配长度的，则返回所有初步匹配结果
    filtered_matches = exact_len_matches if exact_len_matches else initial_matches

    return {name: data[name] for name in filtered_matches if name in data}


class SecurityException(Exception):
    """安全验证异常"""

    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code


def load_or_generate_rsa_keys():
    """加载或生成RSA密钥对"""
    global private_key, public_key

    try:
        # 获取密钥加密密码
        key_password = os.environ.get(KEY_PASSWORD_ENV)
        if not key_password:
            logging.warning(f"环境变量 {KEY_PASSWORD_ENV} 未设置，将使用默认密码")
            # 使用服务器特定信息生成密码（如主机名+MAC地址哈希）
            import uuid
            import socket
            machine_id = str(uuid.getnode()) + socket.gethostname()
            key_password = hashlib.sha256(machine_id.encode()).hexdigest()[:32]
        
        key_password_bytes = key_password.encode('utf-8')  # 转换为字节

        if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
            with open(PRIVATE_KEY_FILE, "rb") as f:
                private_key_data = f.read()
                
            # 尝试判断私钥是否加密
            is_encrypted = b"ENCRYPTED" in private_key_data
            
            if is_encrypted:
                # 私钥已加密，使用密码加载
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=key_password_bytes,
                        backend=default_backend()
                    )
                    logging.info("已成功加载加密的RSA私钥")
                except Exception as e:
                    logging.error(f"无法加载加密私钥: {str(e)}")
                    # 如果加载失败，可能是密码错误，尝试重新生成密钥
                    logging.warning("尝试重新生成密钥对")
                    os.remove(PRIVATE_KEY_FILE)
                    os.remove(PUBLIC_KEY_FILE)
                    # 递归调用自身，走生成新密钥的路径
                    return load_or_generate_rsa_keys()
            else:
                # 私钥未加密，无需密码加载
                try:
                    private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                    logging.info("已加载未加密的RSA私钥，将重新保存为加密格式")
                    
                    # 重新保存为加密格式
                    with open(PRIVATE_KEY_FILE, "wb") as f:
                        f.write(private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.BestAvailableEncryption(key_password_bytes)
                        ))
                    logging.info("RSA私钥已重新保存为加密格式")
                except Exception as e:
                    logging.error(f"无法加载未加密私钥: {str(e)}")
                    raise
                
            with open(PUBLIC_KEY_FILE, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            logging.info("RSA密钥对加载成功")
        else:
            logging.info("未找到RSA密钥文件，正在生成新的密钥对")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # 使用密码加密保存私钥
            with open(PRIVATE_KEY_FILE, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(key_password_bytes)
                ))
            logging.info(f"RSA私钥已加密保存到 {PRIVATE_KEY_FILE}")

            # 保存公钥
            with open(PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            logging.info(f"RSA公钥已保存到 {PUBLIC_KEY_FILE}")
    except Exception as e:
        logging.critical(f"初始化RSA密钥失败: {str(e)}")
        raise


def decrypt_aes(data, key, iv):
    """AES-CBC解密"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def encrypt_data(data_bytes, key, iv):
    """AES-CBC加密"""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()


def verify_device_code(device_code):
    """验证设备码格式"""
    return bool(DEVICE_CODE_REGEX.match(device_code))


def generate_invite_code(device_code):
    """生成邀请码"""
    signature = private_key.sign(
        device_code.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def log_query(account, action, query, result_count, ip):
    """记录查询日志"""
    # 只记录以下操作：
    # 1. 查询学生接口 (query_students)
    # 2. 登录相关 (login_success, login_failed_*)
    # 3. 注册相关 (register_success, register_failed_*)
    # 4. 验证邀请码 (verify_invite_success, verify_invite_failed_*)
    allowed_actions = [
        "query_students",  # 查询学生
        "login_success", "login_failed_password", "login_failed_not_found", "login_failed_device_mismatch",  # 登录相关
        "register_success", "register_failed_invite_verification", "register_failed_account_exists", "register_failed_invalid_device_code_format", "register_failed_password_strength", "register_failed_storage_error",  # 注册相关
        "verify_invite_success", "verify_invite_failed_signature", "verify_invite_failed_missing_fields", "verify_invite_failed_invalid_device_format"  # 验证邀请码相关
    ]
    
    # 如果不是允许的操作，直接返回
    if action not in allowed_actions:
        return
        
    record = {
        "timestamp": datetime.now().isoformat(),
        "account": account,
        "ip": ip,
        "action": action,
        "query": query,
        "result_count": result_count
    }
    
    try:
        # 如果文件不存在或者是第一次写入，直接创建新文件
        if not os.path.exists(QUERY_RECORDS_FILE) or os.path.getsize(QUERY_RECORDS_FILE) == 0:
            with open(QUERY_RECORDS_FILE, "w", encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            return
            
        # 读取现有记录，只保留允许的操作
        existing_records = []
        try:
            with open(QUERY_RECORDS_FILE, "r", encoding='utf-8') as f:
                for line in f:
                    try:
                        existing_record = json.loads(line)
                        if existing_record.get("action") in allowed_actions:
                            existing_records.append(existing_record)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logging.error(f"读取现有记录失败: {str(e)}")
            
        # 添加新记录
        existing_records.append(record)
        
        # 按时间戳排序，最新的在前面
        existing_records.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        
        # 只保留最近的1000条记录
        if len(existing_records) > 1000:
            existing_records = existing_records[:1000]
            
        # 重写文件
        with open(QUERY_RECORDS_FILE, "w", encoding='utf-8') as f:
            for r in existing_records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                
        # 更新缓存
        global QUERY_RECORDS_CACHE
        QUERY_RECORDS_CACHE["data"] = existing_records
        QUERY_RECORDS_CACHE["last_modified"] = os.path.getmtime(QUERY_RECORDS_FILE)
        
    except Exception as e:
        logging.error(f"保存查询记录失败: {str(e)}")


def require_token(f):
    """Token验证装饰器"""

    @wraps(f)
    def decorated(*args, **kwargs):
        # 获取请求头中的token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            raise SecurityException("Missing or invalid Authorization header", 401)

        token = auth_header[7:]  # 去掉'Bearer '前缀

        # 验证token
        if token not in TOKENS:
            raise SecurityException("Invalid or expired token", 401)

        token_data = TOKENS[token]
        if datetime.now() > token_data["expiry"]:
            # 清理过期token
            del TOKENS[token]
            raise SecurityException("Token expired", 401)

        # 将用户信息存储在g对象中
        g.account = token_data["account"]
        g.device_code = token_data["device_code"]
        g.role = token_data.get("role", USER_ROLE) # 从token中获取角色，默认为user

        return f(*args, **kwargs)

    return decorated


def require_auth(f):
    """认证装饰器（带调试信息输出和安全检查）"""

    @wraps(f)
    def decorated(*args, **kwargs):
        # 获取请求头
        encrypted_key_b64 = request.headers.get('X-Encrypted-Key')
        client_sig = request.headers.get('X-Signature')
        client_nonce = request.headers.get('X-Nonce')
        client_timestamp_str = request.headers.get('X-Timestamp')
        
        # 获取客户端真实IP地址，不再信任客户端提供的IP
        client_ip = get_client_ip()
        
        # 安全检查
        if not is_valid_ip(client_ip):
            logging.warning(f"无效的IP地址格式: {client_ip}")
            raise SecurityException("Invalid IP address format", 400)
        
        # 检查IP是否在黑名单中
        if client_ip in blacklist_ips:
            log_suspicious_activity(client_ip, "blacklisted_access_attempt", "黑名单IP尝试访问")
            raise SecurityException("Access denied: IP is blacklisted", 403)
        
        # 检查IP是否被锁定
        if check_login_attempts(client_ip):
            log_suspicious_activity(client_ip, "blocked_access_attempt", "尝试在锁定期间访问")
            raise SecurityException("IP address is temporarily blocked", 429)
        
        # 检查速率限制
        if check_rate_limit(client_ip):
            log_suspicious_activity(client_ip, "rate_limit_exceeded", f"超过速率限制 {RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}s")
            raise SecurityException("Rate limit exceeded", 429)
        
        # 检查请求大小
        content_length = request.content_length
        if content_length and content_length > MAX_REQUEST_SIZE:
            log_suspicious_activity(client_ip, "oversized_request", f"请求大小: {content_length} bytes")
            raise SecurityException("Request too large", 413)
        
        # 验证请求数据的安全性
        if not validate_request_data():
            log_suspicious_activity(client_ip, "invalid_request_data", "请求数据验证失败")
            raise SecurityException("Invalid request data", 400)

        # 调试输出请求头信息（生产环境中应该禁用或降低详细程度）
        if app.debug:
            logging.debug("\n===== 请求头信息 =====")
            logging.debug(f"X-Encrypted-Key: {encrypted_key_b64}")
            logging.debug(f"X-Signature: {client_sig}")
            logging.debug(f"X-Nonce: {client_nonce}")
            logging.debug(f"X-Timestamp: {client_timestamp_str}")
            logging.debug(f"Client IP: {client_ip}")

        if not all([encrypted_key_b64, client_sig, client_nonce, client_timestamp_str]):
            logging.warning(f"Missing auth headers from {client_ip}")
            raise SecurityException("Missing authentication headers", 401)

        try:
            # 时间戳验证 (放宽到30秒窗口，更严格的时间检查)
            current_timestamp_ms = int(datetime.now().timestamp() * 1000)
            client_timestamp_ms = int(client_timestamp_str)
            if abs(current_timestamp_ms - client_timestamp_ms) > 30000:  # 30 seconds
                logging.warning(
                    f"Timestamp validation failed for {client_ip}. Server: {current_timestamp_ms}, Client: {client_timestamp_ms}")
                # 记录安全违规
                record_security_violation(client_ip, "timestamp_invalid")
                raise SecurityException("Invalid timestamp (potential replay attack)", 400)

            # Nonce 验证
            if client_nonce in NONCE_CACHE and current_timestamp_ms - NONCE_CACHE[client_nonce] < NONCE_CACHE_EXPIRY_MS:
                logging.warning(f"Nonce reuse detected for {client_ip}. Nonce: {client_nonce}")
                # 记录可疑活动
                log_suspicious_activity(client_ip, "nonce_reuse", f"Nonce重复使用: {client_nonce}")
                # 记录安全违规
                record_security_violation(client_ip, "nonce_reuse")
                raise SecurityException("Nonce already used (potential replay attack)", 400)

            # 清理过期的Nonce
            keys_to_delete = [k for k, v in NONCE_CACHE.items() if current_timestamp_ms - v >= NONCE_CACHE_EXPIRY_MS]
            for k in keys_to_delete:
                del NONCE_CACHE[k]

            # 验证Nonce格式
            if not re.match(r'^[a-f0-9]{64}$', client_nonce, re.IGNORECASE):
                logging.warning(f"Invalid nonce format from {client_ip}: {client_nonce}")
                raise SecurityException("Invalid nonce format", 400)

            # 记录Nonce使用
            NONCE_CACHE[client_nonce] = current_timestamp_ms

            # 解密AES密钥
            try:
                # 使用PSS填充方案进行解密
                aes_key_raw = base64.b64decode(private_key.decrypt(
                    base64.b64decode(encrypted_key_b64),
                    padding.PKCS1v15()  # 使用PKCS1v15填充方案，与前端保持一致
                ))
                
                # 验证AES密钥长度
                if len(aes_key_raw) != AES_KEY_SIZE:
                    logging.warning(f"Invalid AES key length from {client_ip}: {len(aes_key_raw)} bytes")
                    raise SecurityException("Invalid AES key", 400)
                    
                aes_key_b64_for_sig = base64.b64encode(aes_key_raw).decode('utf-8')
            except Exception as e:
                logging.error(f"AES key decryption failed for {client_ip}: {str(e)}")
                raise SecurityException("Failed to decrypt AES key", 400)

            # 获取请求数据
            path = request.path
            method = request.method.upper()
            request_body_bytes = request.get_data()

            # 获取请求数据
            request_body_string = "" # 初始化为空
            if method != "GET": # GET请求不应该有请求体参与签名原文构建（除非特殊约定）
                try:
                    # 对于非GET请求，如果请求体是JSON，则使用其UTF-8字符串形式
                    # 如果是加密的二进制数据，则使用其Base64编码形式
                    if request_body_bytes:
                        # 尝试解码为json字符串，如果失败，则认为是加密数据，取base64
                        try:
                            request_body_string = request_body_bytes.decode('utf-8')
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            request_body_string = base64.b64encode(request_body_bytes).decode('utf-8')
                except Exception as e:
                    logging.debug(f"Error processing request_body_string for signature: {e}")
                    # 保留 request_body_string 为空字符串，或根据具体错误处理

            # 计算服务器端签名 (SHA-256)
            # 规则: path + method + requestBodyString + aesKeyBase64 + nonce + timestamp
            string_to_sign = f"{path}{method}"

            # 对于GET请求，查询参数直接拼接到path和method之后
            if method == "GET":
                query_params = request.args
                if query_params:
                    sorted_params = sorted(query_params.items(), key=lambda x: x[0])
                    param_str = "&".join(f"{k}={v}" for k, v in sorted_params)
                    string_to_sign += param_str # 追加到签名字符串
                # 对于GET请求，request_body_string 应该为空，所以后续拼接时它不贡献内容
                # 确保 request_body_string 在GET时确实为空
                request_body_string_for_sig = "" 
            else:
                request_body_string_for_sig = request_body_string

            # 添加其他固定部分
            string_to_sign += f"{request_body_string_for_sig}{aes_key_b64_for_sig}{client_nonce}{client_timestamp_str}"

            # 打印详细的签名参数，帮助排查问题
            logging.debug(f"后端签名参数: path={path}, method={method}, body={request_body_string_for_sig}, aesKey={aes_key_b64_for_sig}, nonce={client_nonce}, timestamp={client_timestamp_str}")
            logging.debug(f"后端签名字符串: {string_to_sign}")

            # 使用SHA-256计算签名
            server_sig_calculated = hashlib.sha256(string_to_sign.encode('utf-8')).hexdigest()
            
            # 打印签名结果
            logging.debug(f"后端计算的签名: {server_sig_calculated}, 客户端签名: {client_sig}")

            # 使用常量时间比较函数验证签名，防止时序攻击
            if not secrets.compare_digest(server_sig_calculated, client_sig):
                logging.warning(
                    f"Signature mismatch for {client_ip}. Expected: {server_sig_calculated}, Got: {client_sig}")
                # 记录可疑活动
                log_suspicious_activity(client_ip, "signature_mismatch", "签名验证失败")
                # 记录安全违规
                record_security_violation(client_ip, "signature_mismatch")
                raise SecurityException("Invalid signature", 400)

            logging.info(f"Authentication successful for {client_ip} on path {path}")

            # 将解密后的原始AES密钥和客户端IP存储在g对象中，供后续路由使用
            g.aes_key = aes_key_raw
            g.client_ip = client_ip

            # 如果是POST/PUT/PATCH请求并且有请求体，则解密
            g.decrypted_request_data = None
            if request.method in ['POST', 'PUT', 'PATCH'] and request_body_bytes:
                try:
                    # 先Base64解码请求体
                    decoded_body = base64.b64decode(request_body_bytes)

                    # 分离IV和加密数据
                    iv_from_body = decoded_body[:AES_IV_SIZE]
                    encrypted_body_content = decoded_body[AES_IV_SIZE:]

                    # 解密数据
                    decrypted_body_bytes = decrypt_aes(encrypted_body_content, aes_key_raw, iv_from_body)

                    # 尝试解析为JSON
                    g.decrypted_request_data = json.loads(decrypted_body_bytes.decode('utf-8'))
                    
                    # 验证解密后的数据结构
                    if not isinstance(g.decrypted_request_data, dict):
                        raise ValueError("Decrypted data is not a valid JSON object")
                        
                except json.JSONDecodeError:
                    logging.error(f"JSON解析失败 - 来自 {client_ip}")
                    raise SecurityException("Invalid JSON format in request data", 400)
                except Exception as e:
                    logging.error(f"解密失败 - 错误详情: {str(e)}", exc_info=True)
                    raise SecurityException("Failed to decrypt request data", 400)
            elif request.method in ['GET', 'DELETE'] and request_body_string:
                try:
                    g.decrypted_request_data = json.loads(request_body_string)
                except json.JSONDecodeError:
                    g.decrypted_request_data = request_body_string

        except HTTPException as e:
            logging.error(f"HTTPException during auth: {str(e)}")
            raise
        except SecurityException as e:
            logging.warning(f"SecurityException: {e.message} from {client_ip}")
            return jsonify({"error": e.message}), e.status_code
        except Exception as e:
            logging.error(f"Generic authentication error for {client_ip}: {str(e)}", exc_info=True)
            return jsonify({"error": "Authentication failed"}), 500

        return f(*args, **kwargs)

    return decorated


def require_admin(f):
    """Admin role validation decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'role') or g.role not in [ADMIN_ROLE, SUPERADMIN_ROLE]:
            logging.warning(f"Admin access denied for user {g.account if hasattr(g, 'account') else 'unknown'} to {request.path}")
            raise SecurityException("Administrator privileges required", 403)
        return f(*args, **kwargs)
    return decorated_function


def require_superadmin(f):
    """Super admin role validation decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(g, 'role') or g.role != SUPERADMIN_ROLE:
            logging.warning(f"Super admin access denied for user {g.account if hasattr(g, 'account') else 'unknown'} to {request.path}")
            raise SecurityException("Super administrator privileges required", 403)
        return f(*args, **kwargs)
    return decorated_function


def _build_cors_preflight_response():
    """处理CORS预检请求的辅助函数"""
    response = jsonify({'message': 'CORS preflight successful'})
    # 已经在CORS(app, ...)中全局设置，但为了明确，可以再次添加，或依赖全局配置
    # response.headers.add("Access-Control-Allow-Origin", "*")
    # response.headers.add("Access-Control-Allow-Headers", "*")
    # response.headers.add("Access-Control-Allow-Methods", "*")
    return response, 200


@app.errorhandler(SecurityException)
def handle_security_exception(e):
    """处理安全异常"""
    response = jsonify({"message": e.message})
    response.status_code = e.status_code
    return response


@app.route('/api/auth/public-key', methods=['GET'])
def get_public_key():
    """提供服务器的RSA公钥"""
    if not public_key:
        logging.error("RSA public key not loaded at /api/auth/public-key")
        return jsonify({"error": "Server error: public key not available"}), 500

    try:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # 公钥通常不需要加密响应，因为它是公开的
        return jsonify({"public_key": public_key_pem.decode('utf-8')})
    except Exception as e:
        logging.error(f"Error providing public key: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to provide public key"}), 500


def is_device_blocked(device_code):
    """检查设备码是否被封禁
    
    Args:
        device_code: 设备码
        
    Returns:
        bool: 是否被封禁
    """
    try:
        if not os.path.exists("blocked_device_codes.json"):
            return False
            
        with open("blocked_device_codes.json", "r", encoding='utf-8') as f:
            try:
                blocked_devices = json.load(f)
                return device_code in blocked_devices
            except json.JSONDecodeError:
                return False
    except Exception as e:
        logging.error(f"检查设备码封禁状态失败: {str(e)}")
        return False

@app.route('/api/verify_invite', methods=['POST'])
@require_auth
def verify_invite():
    """验证邀请码接口"""
    try:
        if not g.decrypted_request_data:
            raise SecurityException("Missing verification data in request body", 400)

        device_code = g.decrypted_request_data.get('device_code')
        invite_code = g.decrypted_request_data.get('invite_code')
        client_ip = g.client_ip  # From require_auth
        # account = g.decrypted_request_data.get('account') # Assuming account might be part of request for logging, if available
        # For verify_invite, account context might not be established yet, so using a placeholder or device_id for logging.
        log_account_identifier = device_code  # Or a generic identifier if account not available

        if not all([device_code, invite_code]):
            log_query(log_account_identifier, "verify_invite_failed_missing_fields", {"device_code": device_code}, 0,
                      client_ip)
            raise SecurityException("Missing required fields (device_code, invite_code)", 400)

        if not verify_device_code(device_code):
            log_query(log_account_identifier, "verify_invite_failed_invalid_device_format",
                      {"device_code": device_code}, 0, client_ip)
            raise SecurityException("Invalid device code format", 400)
            
        # 检查设备码是否被封禁
        if is_device_blocked(device_code):
            log_suspicious_activity(client_ip, "blocked_device_access_attempt", f"被封禁的设备码尝试访问: {device_code}")
            raise SecurityException("设备已被封禁", 403)

        # 验证签名
        try:
            signature_bytes = base64.b64decode(invite_code)
            public_key.verify(
                signature_bytes,
                device_code.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH  # Consistent with generation
                ),
                hashes.SHA256()
            )
            logging.info(f"Invite code successfully verified for device_code: {device_code} from IP: {client_ip}")
        except Exception as e:
            logging.warning(
                f"Invite code verification failed for device_code {device_code} from IP {client_ip}: {str(e)}")
            log_query(log_account_identifier, "verify_invite_failed_signature", {"device_code": device_code}, 0,
                      client_ip)
            # 记录邀请码验证失败
            record_security_violation(client_ip, "invite_code_failure", device_code)
            raise SecurityException("Invite code verification failed", 403)

        # 邀请码验证成功
        log_query(log_account_identifier, "verify_invite_success", {"device_code": device_code}, 1, client_ip)

        response_data = {
            "status": "success",
            "message": "邀请码验证成功",
            "device_code": device_code
        }

        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content

        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        # SecurityExceptions are already logged by the decorator or the exception handler
        raise
    except Exception as e:
        # Log unexpected errors within the route handler
        logging.error(
            f"Unexpected error in /api/verify_invite for IP {g.client_ip if hasattr(g, 'client_ip') else 'unknown'}: {str(e)}",
            exc_info=True)
        # Return a generic error response, avoid leaking details
        # The errorhandler for SecurityException will catch this if we re-raise, 
        # or we can return a generic 500 here if it's not a SecurityException.
        # For consistency, let's wrap it in a SecurityException if it's not one already.
        if not isinstance(e, SecurityException):
            raise SecurityException("An unexpected error occurred during invite verification", 500)
        raise  # Re-raise if it was already a SecurityException


@app.route('/api/students', methods=['GET'])
@require_auth
@require_token
def get_students():
    """查询学生报名信息"""
    try:
        # 确保g对象中有aes_key，由require_auth设置
        if not hasattr(g, 'aes_key') or not g.aes_key:
            logging.error(
                f"AES key not found in g for /api/students from IP {g.client_ip if hasattr(g, 'client_ip') else 'unknown'}")
            raise SecurityException("Session not properly initialized for data encryption", 500)

        name = request.args.get('name', '').strip()
        class_name = request.args.get('class', '').strip()
        client_ip = g.client_ip  # From require_auth
        account_for_log = g.account

        # 加载本地缓存的学生数据
        try:
            with open("result.json", "r", encoding="utf-8") as f:
                student_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Failed to load student data: {str(e)}")
            raise SecurityException("Student data not available", 500)

        # 将数据转换为列表格式
        all_students = []
        for name_records in student_data.values():
            for record in name_records:
                student = {
                    "term": record.get(FIELD_MAPPING_INV["学期"]),
                    "register_time": record.get(FIELD_MAPPING_INV["报名时间"]),
                    "id_card": record.get(FIELD_MAPPING_INV["身份证号"]),
                    "name": record.get(FIELD_MAPPING_INV["姓名"]),
                    "class": record.get(FIELD_MAPPING_INV["班级"]),
                    "grade": record.get(FIELD_MAPPING_INV["年级"]),
                    "course": record.get(FIELD_MAPPING_INV["课程"]),
                    "course_type": record.get(FIELD_MAPPING_INV["课程类型"]),
                    "teacher": record.get(FIELD_MAPPING_INV["任课教师"]),
                    "time": record.get(FIELD_MAPPING_INV["上课时间"]),
                    "max_students": record.get(FIELD_MAPPING_INV["报名人数上限"]),
                    "current_students": record.get(FIELD_MAPPING_INV["已报名人数"]),
                    "notes": record.get(FIELD_MAPPING_INV["备注"]),
                    "confirm_info": record.get(FIELD_MAPPING_INV["确认信息"])
                }
                all_students.append(student)

        # 过滤结果
        filtered_students = all_students
        if name:
            # 使用模糊匹配
            from difflib import get_close_matches
            name_matches = get_close_matches(name, [s["name"] for s in filtered_students], n=10, cutoff=0.4)
            filtered_students = [s for s in filtered_students if s["name"] in name_matches]
        if class_name:
            # 解析并标准化班级查询字符串
            normalized_class = parse_class_query(class_name)
            filtered_students = [s for s in filtered_students if normalized_class in parse_class_query(s["class"])]

        log_query(account_for_log, "query_students",
                  {"name": name, "class": class_name},
                  len(filtered_students), client_ip)

        # 准备响应数据
        response_data = {"students": filtered_students}
        print(f"Response data: {response_data}")  # 打印响应数据
        response_data_bytes = json.dumps(response_data, ensure_ascii=False).encode('utf-8')

        # 加密响应数据
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content

        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        client_ip_for_log = g.client_ip if hasattr(g, 'client_ip') else 'unknown'
        logging.error(f"Error in /api/students for IP {client_ip_for_log}: {str(e)}", exc_info=True)
        raise SecurityException("An error occurred while fetching student data.", 500)


@app.route('/api/auth/register', methods=['POST'])
@require_auth  # This decorator will handle decryption and place data in g.decrypted_request_data
def handle_register():
    """用户注册接口"""
    try:
        if not g.decrypted_request_data:
            raise SecurityException("Missing registration data in request body", 400)

        device_code = g.decrypted_request_data.get('device_code')
        invite_code = g.decrypted_request_data.get('invite_code')
        account = g.decrypted_request_data.get('account')
        password = g.decrypted_request_data.get('password')
        client_ip = g.client_ip  # From require_auth

        if not all([device_code, invite_code, account, password]):
            raise SecurityException(
                "Missing required fields for registration (device_code, invite_code, account, password)", 400)

        # 验证设备码格式
        if not verify_device_code(device_code):
            log_query(account, "register_failed_invalid_device_code_format",
                      {"account": account, "device_code": device_code}, 0, client_ip)
            raise SecurityException("无效设备码格式", 400)
            
        # 检查设备码是否被封禁
        if is_device_blocked(device_code):
            log_suspicious_activity(client_ip, "blocked_device_registration_attempt", f"被封禁的设备码尝试注册: {device_code}")
            raise SecurityException("设备已被封禁", 403)

        # 验证密码强度
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$', password):
            log_query(account, "register_failed_password_strength",
                      {"account": account}, 0, client_ip)
            raise SecurityException("密码必须包含大小写字母和数字，且长度至少为6位", 400)

        # 验证邀请码有效性 (针对传入的device_code)
        try:
            signature_bytes = base64.b64decode(invite_code)
            public_key.verify(
                signature_bytes,
                device_code.encode('utf-8'),  # Verify against the device_code from the registration request
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH  # Consistent with generation
                ),
                hashes.SHA256()
            )
        except Exception as e:
            log_query(account, "register_failed_invite_verification", {"account": account, "device_code": device_code},
                      0, client_ip)
            # 记录邀请码验证失败
            record_security_violation(client_ip, "invite_code_failure", device_code)
            raise SecurityException("邀请码验证失败", 403)

        # 检查用户是否已存在
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                for line in f:
                    try:
                        existing_user = json.loads(line)
                        if existing_user.get('account') == account:
                            log_query(account, "register_failed_account_exists", {"account": account}, 0, client_ip)
                            raise SecurityException("账号已存在", 409)  # 409 Conflict
                    except json.JSONDecodeError:
                        logging.warning(
                            f"Skipping malformed line in {USERS_FILE} during registration check: {line.strip()}")

        # 存储用户信息
        # 检查是否是第一个用户，如果是，则设为admin
        is_first_user = not os.path.exists(USERS_FILE) or os.path.getsize(USERS_FILE) == 0
        user_role = ADMIN_ROLE if is_first_user else USER_ROLE

        user_data = {
            'account': account,
            'password_hash': hash_password(password),
            'device_code': device_code,  # Store the device_code used for registration
            'role': user_role,
            'register_time': datetime.now().isoformat(),
            'last_login_ip': client_ip,
            'last_login_time': datetime.now().isoformat()
        }
        logging.info(f"User {account} will be registered with role: {user_role}")

        # 写入文件
        try:
            with open(USERS_FILE, 'a') as f:
                f.write(json.dumps(user_data, ensure_ascii=False) + '\n')
            logging.info(f"User {account} registered successfully from IP {client_ip} with device_code {device_code}")
        except Exception as e:
            logging.error(f"Failed to write user data for {account} to {USERS_FILE}: {str(e)}", exc_info=True)
            log_query(account, "register_failed_storage_error", {"account": account}, 0, client_ip)
            raise SecurityException("注册信息存储失败", 500)

        log_query(account, "register_success", {"account": account, "device_code": device_code}, 1, client_ip)

        # 加密成功响应
        response_data = {"status": "success", "message": "注册成功"}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content

        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"注册异常: {str(e)}")
        raise SecurityException("注册过程发生错误", 500)


@app.route('/api/auth/login', methods=['POST'])
@require_auth
def handle_login():
    """用户登录接口"""
    try:
        # 解密后的数据在g.decrypted_request_data
        if not g.decrypted_request_data:
            raise SecurityException("Missing login credentials in request body", 400)

        account = g.decrypted_request_data.get('account')
        password = g.decrypted_request_data.get('password')
        device_code_from_request = g.decrypted_request_data.get('device_code')
        client_ip = g.client_ip

        if not all([account, password, device_code_from_request]):
            raise SecurityException("Missing account, password, or device_code in login request", 400)

        # 验证用户凭证
        users = []
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                for line in f:
                    try:
                        users.append(json.loads(line))
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping malformed line in {USERS_FILE}: {line.strip()}")

        user_found = False
        for user in users:
            if user.get('account') == account:
                user_found = True
                if verify_password(password, user.get('password_hash')):
                    # 验证设备码绑定
                    if user.get('device_code') != device_code_from_request:
                        log_query(account, "login_failed_device_mismatch", {"account": account}, 0, client_ip)
                        record_failed_login(client_ip)
                        log_suspicious_activity(client_ip, "failed_login", f"设备码不匹配 - 账号: {account}")
                        raise SecurityException("Device code does not match registered device", 403)

                    # 登录成功，记录日志
                    log_query(account, "login_success", {"account": account}, 1, client_ip)

                    # 更新用户最后登录信息
                    for i, u in enumerate(users):
                        if u.get('account') == account:
                            users[i]['last_login_ip'] = client_ip
                            users[i]['last_login_time'] = datetime.now().isoformat()
                            break
                    
                    # 写回用户文件
                    try:
                        with open(USERS_FILE, 'w') as f:
                            for u in users:
                                f.write(json.dumps(u) + '\n')
                    except Exception as e:
                        logging.error(f"更新用户登录信息失败: {str(e)}")
                        # 继续处理，不影响登录流程

                    # 先清除该账户的所有现有token
                    tokens_to_remove = []
                    for token_key, token_data in TOKENS.items():
                        if token_data.get("account") == account:
                            tokens_to_remove.append(token_key)
                    
                    for token_key in tokens_to_remove:
                        del TOKENS[token_key]
                        logging.info(f"删除账户 {account} 的旧令牌以确保一个账户只有一个有效令牌")

                    # 生成新的访问令牌
                    token = secrets.token_urlsafe(32)
                    expiry_time = datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

                    # 存储token
                    user_role = user.get('role', USER_ROLE) # 获取用户角色，默认为user
                    TOKENS[token] = {
                        "account": account,
                        "expiry": expiry_time,
                        "device_code": device_code_from_request,
                        "role": user_role
                    }
                    
                    # 持久化保存令牌
                    save_tokens()

                    # 构建用户信息对象，与前端期望格式一致
                    user_info = {
                        "account": account,
                        "role": user_role, # 使用从用户数据中获取的角色
                        "registerTime": user.get('register_time', datetime.now().isoformat())
                    }
                    
                    response_data = {
                        "token": token,
                        "expiry": expiry_time.isoformat(),
                        "user": user_info
                    }

                    # 加密响应数据
                    response_data_bytes = json.dumps(response_data).encode('utf-8')
                    iv = os.urandom(AES_IV_SIZE)
                    encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)

                    # IV需要和密文一起发送给客户端
                    full_response_body = iv + encrypted_response_content

                    # Base64编码整个响应体 (IV + 密文)
                    # 客户端需要先Base64解码，然后分离IV和密文进行解密
                    return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
                else:
                    log_query(account, "login_failed_password", {"account": account}, 0, client_ip)
                    record_failed_login(client_ip)
                    log_suspicious_activity(client_ip, "failed_login", f"密码错误 - 账号: {account}")
                    raise SecurityException("Invalid account or password", 401)

        if not user_found:
            log_query(account if account else "unknown_user", "login_failed_not_found", {"account": account}, 0,
                      client_ip)
            record_failed_login(client_ip)
            log_suspicious_activity(client_ip, "failed_login", f"账号不存在 - 账号: {account}")
            raise SecurityException("Invalid account or password", 401)

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"登录异常: {str(e)}", exc_info=True)
        raise SecurityException("登录过程发生错误", 500)


@app.route('/api/auth/updatekey', methods=['POST'])
@require_auth
@require_token
def update_key():
    """更新客户端密钥接口"""
    try:
        account = g.account
        client_ip = g.client_ip
        
        # 记录密钥更新操作
        log_query(account, "update_key", {"account": account}, 1, client_ip)
        
        # 构建响应数据
        response_data = {
            "status": "success",
            "message": "密钥更新成功"
        }
        
        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"更新密钥异常: {str(e)}", exc_info=True)
        raise SecurityException("更新密钥过程发生错误", 500)


@app.route('/api/auth/login-records', methods=['GET', 'POST'])
@require_auth
@require_token
def get_login_records():
    """获取登录记录接口"""
    try:
        account = g.account
        client_ip = g.client_ip # 当前请求的IP，可能与记录中的IP不同

        # 使用缓存加载所有记录
        all_records = load_query_records()
        
        # 筛选当前账户的登录记录
        login_records = []
        for record in all_records:
            # 筛选属于当前账户的登录尝试记录 (成功或失败)
            if record.get('account') == account and \
               ('login_success' == record.get('action') or 'login_failed' in record.get('action')):
                login_records.append({
                    "time": record.get('timestamp'),
                    "ip": record.get('ip'),
                    "status": 'success' if 'login_success' == record.get('action') else 'failed',
                    "reason": record.get('query', {}).get('reason', '') if 'login_failed' in record.get('action') else ''
                })
        
        # 按时间倒序排序，最新的记录在前面
        login_records.sort(key=lambda x: x['time'], reverse=True)

        log_query(account, "get_login_records", {"account": account}, len(login_records), client_ip)

        # 准备响应数据
        response_data = login_records
        response_data_bytes = json.dumps(response_data, ensure_ascii=False).encode('utf-8')

        # 加密响应数据
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content

        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"获取登录记录异常: {str(e)}", exc_info=True)
        raise SecurityException("获取登录记录过程发生错误", 500)


@app.route('/api/export-students', methods=['GET'])
@require_auth
@require_token
def export_students():
    """导出学生数据接口"""
    try:
        account = g.account
        client_ip = g.client_ip
        log_query(account, "export_students", {"account": account}, 0, client_ip)

        # 此处应实现导出逻辑，例如生成CSV或Excel文件
        # 目前仅返回成功占位符
        response_data = {
            "status": "success",
            "message": "学生数据导出功能待实现"
        }
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"导出学生数据异常: {str(e)}", exc_info=True)
        raise SecurityException("导出学生数据过程发生错误", 500)


@app.route('/api/admin/logs', methods=['GET'])
@require_auth
@require_token
@require_admin
def get_admin_logs():
    """获取管理员操作日志接口"""
    try:
        account = g.account
        client_ip = g.client_ip
        log_query(account, "get_admin_logs", {"account": account}, 0, client_ip)

        # 使用缓存加载所有记录
        admin_logs = load_query_records()
        admin_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        response_data = {"logs": admin_logs[:100]} # 示例：返回最近100条
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"获取管理员日志异常: {str(e)}", exc_info=True)
        raise SecurityException("获取管理员日志过程发生错误", 500)


# Admin routes
@app.route('/api/admin/users/query', methods=['GET'])
@require_auth
@require_token
@require_admin
def admin_get_users():
    # TODO: Implement user query logic
    users_data = [] # Placeholder
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    user = json.loads(line)
                    users_data.append({
                        "account": user.get("account"),
                        "role": user.get("role"),
                        "deviceCode": user.get("device_code"),
                        "registerTime": user.get("register_time"),
                        "lastLoginTime": user.get("last_login_time")
                    })
                except json.JSONDecodeError:
                    continue
    response_data = {"data": users_data}
    response_data_bytes = json.dumps(response_data).encode('utf-8')
    iv = os.urandom(AES_IV_SIZE)
    encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
    full_response_body = iv + encrypted_response_content
    return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})


@app.route('/api/admin/logs', methods=['GET'], endpoint='get_admin_logs_paginated') # Ensure OPTIONS is handled
@require_auth
@require_token
@require_admin
def get_admin_logs_paginated():
    try:
        account = g.account
        client_ip = g.client_ip
        page = request.args.get('page', 1, type=int)
        size = request.args.get('size', 10, type=int)

        log_query(account, "get_admin_logs_paginated", {"account": account, "page": page, "size": size}, 0, client_ip)

        # 使用缓存加载所有记录
        all_logs = load_query_records()
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        total_logs = len(all_logs)
        start_index = (page - 1) * size
        end_index = start_index + size
        paginated_logs = all_logs[start_index:end_index]

        response_data = {"data": paginated_logs, "total": total_logs}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"获取管理员日志 (分页) 异常: {str(e)}", exc_info=True)
        raise SecurityException("获取管理员日志过程发生错误", 500)


@app.route('/api/admin/online-users', methods=['GET'])
@require_auth
@require_token
@require_admin
def admin_get_online_users():
    try:
        account = g.account # Admin account performing the action
        client_ip = g.client_ip
        log_query(account, "admin_get_online_users", {"admin_account": account}, 0, client_ip)

        online_users_data = []
        current_time = datetime.now()
        # Iterate over a copy of TOKENS items if modification within loop is possible elsewhere, though not here.
        for token_value, token_data in list(TOKENS.items()): 
            if current_time <= token_data["expiry"]:
                user_detail = {
                    "account": token_data["account"],
                    "ip": "N/A", # Placeholder, ideally get from user's last login record
                    "loginTime": "N/A" # Placeholder, ideally get from user's last login record
                }
                # Attempt to enrich with last login IP and time from USERS_FILE
                if os.path.exists(USERS_FILE):
                    with open(USERS_FILE, 'r', encoding='utf-8') as f_users:
                        for line in f_users:
                            try:
                                u = json.loads(line)
                                if u.get('account') == token_data["account"]:
                                    user_detail["ip"] = u.get('last_login_ip', 'N/A')
                                    user_detail["loginTime"] = u.get('last_login_time', datetime.now().isoformat()) # Fallback to now if not found
                                    break
                            except json.JSONDecodeError:
                                continue
                online_users_data.append(user_detail)
        
        response_data = {"data": online_users_data}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"获取在线用户列表异常: {str(e)}", exc_info=True)
        raise SecurityException("获取在线用户列表过程发生错误", 500)


@app.route('/api/admin/generate-invite', methods=['POST'])
@require_auth
@require_token
@require_admin
def admin_generate_invite():
    try:
        admin_account = g.account # Admin account performing the action
        client_ip = g.client_ip

        if not g.decrypted_request_data:
            raise SecurityException("Missing device_code in request body for invite generation", 400)
        
        device_code_to_invite = g.decrypted_request_data.get('device_code')
        if not device_code_to_invite:
            log_query(admin_account, "admin_generate_invite_failed_missing_device_code", {"admin_account": admin_account}, 0, client_ip)
            raise SecurityException("Device code is required for invite generation", 400)

        if not verify_device_code(device_code_to_invite):
            log_query(admin_account, "admin_generate_invite_failed_invalid_device_format", {"admin_account": admin_account, "target_device_code": device_code_to_invite}, 0, client_ip)
            raise SecurityException("Invalid device code format for invite generation", 400)

        invite_code = generate_invite_code(device_code_to_invite)
        log_query(admin_account, "admin_generate_invite_success", {"admin_account": admin_account, "generated_for_device_code": device_code_to_invite}, 1, client_ip)

        response_data = {"data": {"invite_code": invite_code}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"管理员生成邀请码异常: {str(e)}", exc_info=True)
        raise SecurityException("管理员生成邀请码过程发生错误", 500)


@app.route('/api/admin/reset-password', methods=['POST'])
@require_auth
@require_token
@require_admin
def admin_reset_password():
    try:
        admin_account = g.account # Admin performing the action
        client_ip = g.client_ip

        if not g.decrypted_request_data:
            raise SecurityException("Missing data in request body for password reset", 400)
        
        target_account = g.decrypted_request_data.get('account')
        new_password = g.decrypted_request_data.get('new_password')

        if not all([target_account, new_password]):
            log_query(admin_account, "admin_reset_password_failed_missing_fields", {"admin_account": admin_account}, 0, client_ip)
            raise SecurityException("Target account and new password are required", 400)

        # Password complexity validation (optional, but good practice)
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{6,}$', new_password):
            log_query(admin_account, "admin_reset_password_failed_complexity", {"admin_account": admin_account, "target_account": target_account}, 0, client_ip)
            raise SecurityException("New password does not meet complexity requirements", 400)

        users = []
        user_found = False
        user_index = -1
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    try:
                        user = json.loads(line)
                        users.append(user)
                        if user.get('account') == target_account:
                            user_found = True
                            user_index = i
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping malformed line in {USERS_FILE} during password reset: {line.strip()}")
        
        if not user_found:
            log_query(admin_account, "admin_reset_password_failed_user_not_found", {"admin_account": admin_account, "target_account": target_account}, 0, client_ip)
            raise SecurityException(f"User {target_account} not found for password reset", 404)

        users[user_index]['password_hash'] = hash_password(new_password)

        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for user_data in users:
                f.write(json.dumps(user_data, ensure_ascii=False) + '\n')
        
        log_query(admin_account, "admin_reset_password_success", {"admin_account": admin_account, "target_account": target_account}, 1, client_ip)

        response_data = {"data": {"message": "Password reset successfully for user " + target_account}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"管理员重置密码异常: {str(e)}", exc_info=True)
        raise SecurityException("管理员重置密码过程发生错误", 500)


@app.route('/api/admin/users/delete', methods=['POST']) # Frontend uses POST for this
@require_auth
@require_token
@require_admin
def admin_delete_user():
    try:
        admin_account = g.account # Admin performing the action
        client_ip = g.client_ip

        if not g.decrypted_request_data:
            raise SecurityException("Missing account in request body for user deletion", 400)
        
        target_account_to_delete = g.decrypted_request_data.get('account')
        if not target_account_to_delete:
            log_query(admin_account, "admin_delete_user_failed_missing_account", {"admin_account": admin_account}, 0, client_ip)
            raise SecurityException("Account to delete is required", 400)

        if target_account_to_delete == admin_account:
            log_query(admin_account, "admin_delete_user_failed_self_delete", {"admin_account": admin_account}, 0, client_ip)
            raise SecurityException("Admin users cannot delete themselves via this endpoint.", 403)

        users_after_deletion = []
        user_found_to_delete = False
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        user = json.loads(line)
                        if user.get('account') == target_account_to_delete:
                            if user.get('role') == ADMIN_ROLE:
                                log_query(admin_account, "admin_delete_user_failed_delete_admin", {"admin_account": admin_account, "target_admin": target_account_to_delete}, 0, client_ip)
                                raise SecurityException("Cannot delete another admin user.", 403)
                            user_found_to_delete = True
                            # Don't add this user to users_after_deletion
                        else:
                            users_after_deletion.append(user)
                    except json.JSONDecodeError:
                        logging.warning(f"Skipping malformed line in {USERS_FILE} during user deletion: {line.strip()}")
                        users_after_deletion.append(json.loads(line)) # Or handle error more gracefully
        
        if not user_found_to_delete:
            log_query(admin_account, "admin_delete_user_failed_not_found", {"admin_account": admin_account, "target_account": target_account_to_delete}, 0, client_ip)
            raise SecurityException(f"User {target_account_to_delete} not found for deletion.", 404)

        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            for user_data in users_after_deletion:
                f.write(json.dumps(user_data, ensure_ascii=False) + '\n')
        
        log_query(admin_account, "admin_delete_user_success", {"admin_account": admin_account, "deleted_account": target_account_to_delete}, 1, client_ip)

        response_data = {"data": {"message": f"User {target_account_to_delete} deleted successfully."}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"管理员删除用户异常: {str(e)}", exc_info=True)
        raise SecurityException("管理员删除用户过程发生错误", 500)


@app.route('/api/admin/export-logs', methods=['GET'])
@require_auth
@require_token
@require_admin
def admin_export_logs():

    try:
        admin_account = g.account
        client_ip = g.client_ip
        log_query(admin_account, "admin_export_logs_attempt", {"admin_account": admin_account}, 0, client_ip)

        # Actual implementation would generate a file (e.g., CSV, XLSX)
        # For simplicity, this example returns all logs as JSON, similar to get_admin_logs.
        # Frontend expects a blob, so this needs adjustment if direct file download is required.
        # For now, returning JSON data that client might need to process into a file.
        all_logs = []
        if os.path.exists(QUERY_RECORDS_FILE):
            with open(QUERY_RECORDS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        record = json.loads(line)
                        all_logs.append(record)
                    except json.JSONDecodeError:
                        continue
        all_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        # This is NOT a file download. Client side needs to handle this data to create a file.
        # If direct download: from flask import send_file; and set Content-Type, Content-Disposition.
        # And response should not be encrypted in that case.
        response_data = {"data": all_logs, "message": "Log data for export. Client should process this into a file."}
        response_data_bytes = json.dumps(response_data, ensure_ascii=False).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"管理员导出日志异常: {str(e)}", exc_info=True)
        raise SecurityException("管理员导出日志过程发生错误", 500)


@app.route('/api/admin/force-logout', methods=['POST'])
@require_auth
@require_token
@require_admin
def admin_force_logout():
    """管理员强制用户登出"""
    try:
        if not g.decrypted_request_data:
            raise SecurityException("Missing data in request body", 400)

        target_account = g.decrypted_request_data.get('account')
        client_ip = g.client_ip
        admin_account = g.account

        if not target_account:
            raise SecurityException("Missing target account", 400)

        # 查找该用户的所有令牌
        tokens_to_remove = []
        for token, data in TOKENS.items():
            if data.get("account") == target_account:
                tokens_to_remove.append(token)

        if not tokens_to_remove:
            # 用户可能没有活跃会话
            response_data = {
                "status": "success",
                "message": f"用户 {target_account} 没有活跃会话"
            }
        else:
            # 删除该用户的所有令牌
            for token in tokens_to_remove:
                del TOKENS[token]
                
            # 持久化保存令牌
            save_tokens()
                
            logging.info(f"管理员 {admin_account} 强制登出用户 {target_account}")
            
            response_data = {
                "status": "success",
                "message": f"已强制登出用户 {target_account}，删除了 {len(tokens_to_remove)} 个会话"
            }

        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content

        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})

    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"强制登出用户失败: {str(e)}", exc_info=True)
        raise SecurityException("强制登出用户失败", 500)


@app.route('/api/admin/system-status', methods=['GET'])
@require_auth
@require_token
@require_admin
def get_system_status():

    """获取系统状态接口"""
    try:
        account = g.account
        client_ip = g.client_ip
        log_query(account, "get_system_status", {"account": account}, 0, client_ip)

        # 此处应实现获取系统状态的逻辑
        # 例如：CPU使用率、内存使用率、活动用户数等
        system_status = {
            "cpu_usage": "N/A",
            "memory_usage": "N/A",
            "active_users": len(TOKENS),
            "total_queries_today": 0 # 需要实现统计逻辑
        }
        response_data = {"status": system_status}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"获取系统状态异常: {str(e)}", exc_info=True)
        raise SecurityException("获取系统状态过程发生错误", 500)


@app.before_request
def cleanup_expired_tokens():
    """清理过期的令牌"""
    global TOKENS
    
    # 只在请求处理前执行，避免频繁IO
    if request.endpoint == 'static' or request.path.startswith('/favicon'):
        return
        
    current_time = datetime.now()
    tokens_to_remove = []
    
    for token, data in TOKENS.items():
        if current_time > data["expiry"]:
            tokens_to_remove.append(token)
            
    if tokens_to_remove:
        for token in tokens_to_remove:
            del TOKENS[token]
        # 只有在有过期令牌被删除时才写入文件
        save_tokens()
        logging.info(f"已清理 {len(tokens_to_remove)} 个过期令牌")


# 黑名单IP存储
blacklist_ips = set()
BLACKLIST_IPS_FILE = "blacklist_ips.json"

# 加载黑名单IP
def load_blacklist_ips():
    """加载黑名单IP"""
    global blacklist_ips
    try:
        if os.path.exists(BLACKLIST_IPS_FILE):
            with open(BLACKLIST_IPS_FILE, 'r') as f:
                blacklist_ips = set(json.load(f))
                logging.info(f"已加载 {len(blacklist_ips)} 个黑名单IP地址")
        else:
            logging.warning(f"黑名单文件 {BLACKLIST_IPS_FILE} 不存在，将创建新文件")
            with open(BLACKLIST_IPS_FILE, 'w') as f:
                json.dump([], f)
    except Exception as e:
        logging.error(f"加载黑名单IP失败: {str(e)}")
        blacklist_ips = set()

# 保存黑名单IP
def save_blacklist_ips():
    """保存黑名单IP"""
    try:
        with open(BLACKLIST_IPS_FILE, 'w') as f:
            json.dump(list(blacklist_ips), f)
            logging.info(f"已保存 {len(blacklist_ips)} 个黑名单IP地址")
    except Exception as e:
        logging.error(f"保存黑名单IP失败: {str(e)}")

# 超级管理员功能：激活管理员
@app.route('/api/superadmin/activate-admin', methods=['POST'])
@require_auth
@require_token
@require_superadmin
def activate_admin():
    """激活管理员账号"""
    try:
        superadmin_account = g.account
        client_ip = g.client_ip
        
        # 请求数据已由装饰器解密
        if not g.decrypted_request_data:
            raise SecurityException("Missing decrypted data", 400)
        target_account = g.decrypted_request_data.get('account')
        
        if not target_account:
            raise SecurityException("Missing target account", 400)
        
        # 读取用户文件并更新角色
        users = []
        user_found = False
        
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                for line in f:
                    try:
                        user = json.loads(line)
                        if user.get('account') == target_account:
                            user['role'] = ADMIN_ROLE
                            user_found = True
                        users.append(user)
                    except json.JSONDecodeError:
                        continue
        
        if not user_found:
            raise SecurityException("User not found", 404)
        
        # 写回用户文件
        with open(USERS_FILE, 'w') as f:
            for user in users:
                f.write(json.dumps(user) + '\n')
        
        # 更新活跃token中的角色
        for token_data in TOKENS.values():
            if token_data.get('account') == target_account:
                token_data['role'] = ADMIN_ROLE
        
        log_query(superadmin_account, "superadmin_activate_admin", {"target_account": target_account}, 1, client_ip)
        logging.info(f"Super admin {superadmin_account} activated admin privileges for user {target_account}")
        
        response_data = {"data": {"message": f"User {target_account} has been activated as admin"}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"Activate admin failed: {str(e)}", exc_info=True)
        raise SecurityException("Activate admin process failed", 500)

# 超级管理员功能：拉黑IP
@app.route('/api/superadmin/blacklist-ip', methods=['POST'])
@require_auth
@require_token
@require_superadmin
def blacklist_ip():
    """拉黑IP地址"""
    try:
        superadmin_account = g.account
        client_ip = g.client_ip
        
        # 请求数据已由装饰器解密
        if not g.decrypted_request_data:
            raise SecurityException("Missing decrypted data", 400)
        target_ip = g.decrypted_request_data.get('ip')
        action = g.decrypted_request_data.get('action', 'add')  # add or remove
        
        if not target_ip:
            raise SecurityException("Missing target IP", 400)
        
        # 验证IP格式
        if not is_valid_ip(target_ip):
            raise SecurityException("Invalid IP format", 400)
        
        if action == 'add':
            blacklist_ips.add(target_ip)
            message = f"IP {target_ip} has been blacklisted"
            log_action = "superadmin_blacklist_ip_add"
        elif action == 'remove':
            blacklist_ips.discard(target_ip)
            message = f"IP {target_ip} has been removed from blacklist"
            log_action = "superadmin_blacklist_ip_remove"
        else:
            raise SecurityException("Invalid action", 400)
        
        # 保存黑名单
        save_blacklist_ips()
        
        log_query(superadmin_account, log_action, {"target_ip": target_ip}, 1, client_ip)
        logging.info(f"Super admin {superadmin_account} {action}ed IP {target_ip} to/from blacklist")
        
        response_data = {"data": {"message": message}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"Blacklist IP failed: {str(e)}", exc_info=True)
        raise SecurityException("Blacklist IP process failed", 500)

# 获取黑名单IP列表
@app.route('/api/superadmin/blacklist-ips', methods=['GET'])
@require_auth
@require_token
@require_superadmin
def get_blacklist_ips():
    """获取黑名单IP列表"""
    try:
        superadmin_account = g.account
        client_ip = g.client_ip
        
        log_query(superadmin_account, "superadmin_get_blacklist_ips", {}, len(blacklist_ips), client_ip)
        
        response_data = {"data": {"blacklist_ips": list(blacklist_ips)}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"Get blacklist IPs failed: {str(e)}", exc_info=True)
        raise SecurityException("Get blacklist IPs process failed", 500)

# 超级管理员功能：设置自定义角色
@app.route('/api/superadmin/set-custom-role', methods=['POST'])
@require_auth
@require_token
@require_superadmin
def set_custom_role():
    """设置用户自定义角色"""
    try:
        superadmin_account = g.account
        client_ip = g.client_ip
        
        # 请求数据已由装饰器解密
        if not g.decrypted_request_data:
            raise SecurityException("Missing decrypted data", 400)
        
        target_account = g.decrypted_request_data.get('account')
        custom_role = g.decrypted_request_data.get('role')
        
        if not target_account or not custom_role:
            raise SecurityException("Missing target account or custom role", 400)
        
        # 读取用户文件并更新角色
        users = []
        user_found = False
        
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                for line in f:
                    try:
                        user = json.loads(line)
                        if user.get('account') == target_account:
                            user['role'] = custom_role
                            user_found = True
                        users.append(user)
                    except json.JSONDecodeError:
                        continue
        
        if not user_found:
            raise SecurityException("User not found", 404)
        
        # 写回用户文件
        with open(USERS_FILE, 'w') as f:
            for user in users:
                f.write(json.dumps(user) + '\n')
        
        # 更新活跃token中的角色
        for token_data in TOKENS.values():
            if token_data.get('account') == target_account:
                token_data['role'] = custom_role
        
        log_query(superadmin_account, "superadmin_set_custom_role", 
                 {"target_account": target_account, "custom_role": custom_role}, 1, client_ip)
        logging.info(f"Super admin {superadmin_account} set custom role '{custom_role}' for user {target_account}")
        
        response_data = {"data": {"message": f"User {target_account} has been assigned custom role: {custom_role}"}}
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"Set custom role failed: {str(e)}", exc_info=True)
        raise SecurityException("Set custom role process failed", 500)

@app.route('/api/admin/clear-logs', methods=['POST'])
@require_auth
@require_token
@require_admin
def admin_clear_logs():
    """管理员清除日志接口"""
    try:
        admin_account = g.account
        client_ip = g.client_ip
        
        # 获取请求参数
        if not g.decrypted_request_data:
            raise SecurityException("Missing request data", 400)
            
        log_type = g.decrypted_request_data.get('log_type', 'all')  # 日志类型：all, query, suspicious
        
        # 记录此操作
        log_query(admin_account, "admin_clear_logs", {"admin_account": admin_account, "log_type": log_type}, 0, client_ip)
        
        result_message = ""
        
        # 根据日志类型清除不同的日志
        if log_type in ['all', 'query']:
            # 清除查询记录
            if os.path.exists(QUERY_RECORDS_FILE):
                # 备份原文件
                backup_file = f"{QUERY_RECORDS_FILE}.bak.{int(time.time())}"
                try:
                    shutil.copy2(QUERY_RECORDS_FILE, backup_file)
                    # 清空文件
                    open(QUERY_RECORDS_FILE, 'w', encoding='utf-8').close()
                    # 更新缓存
                    global QUERY_RECORDS_CACHE
                    QUERY_RECORDS_CACHE["data"] = []
                    QUERY_RECORDS_CACHE["last_modified"] = os.path.getmtime(QUERY_RECORDS_FILE)
                    result_message += "查询记录已清除并备份。"
                except Exception as e:
                    logging.error(f"清除查询记录失败: {str(e)}")
                    raise SecurityException("清除查询记录失败", 500)
                    
        if log_type in ['all', 'suspicious']:
            # 清除可疑活动记录
            global suspicious_activities
            suspicious_activities = []
            result_message += "可疑活动记录已清除。"
            
        # 准备响应数据
        response_data = {
            "status": "success",
            "message": result_message
        }
        
        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except SecurityException as se:
        raise
    except Exception as e:
        logging.error(f"清除日志异常: {str(e)}", exc_info=True)
        raise SecurityException("清除日志过程发生错误", 500)

# 密码哈希函数
def hash_password(password):
    """使用Argon2id算法哈希密码
    
    Args:
        password: 明文密码
        
    Returns:
        str: 哈希后的密码
    """
    return argon2.using(
        # 内存成本
        memory_cost=65536,  # 64MB
        # 时间成本
        time_cost=3,        # 3次迭代
        # 并行度
        parallelism=4       # 4个并行线程
    ).hash(password)

def verify_password(password, password_hash):
    """验证密码是否匹配哈希值
    
    Args:
        password: 明文密码
        password_hash: 存储的密码哈希
        
    Returns:
        bool: 密码是否匹配
    """
    # 兼容旧的SHA-256哈希方法
    if len(password_hash) == 64 and all(c in '0123456789abcdef' for c in password_hash.lower()):
        # 这是旧的SHA-256哈希
        return password_hash == hashlib.sha256(password.encode()).hexdigest()
    
    # 使用passlib的验证方法
    return argon2.verify(password, password_hash)

def load_tokens():
    """从文件加载令牌数据"""
    global TOKENS
    
    if not os.path.exists(TOKENS_FILE):
        TOKENS = {}
        # 创建空的令牌文件
        try:
            with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
                json.dump({}, f)
            logging.info(f"创建了新的令牌文件 {TOKENS_FILE}")
        except Exception as e:
            logging.error(f"创建令牌文件失败: {str(e)}")
        return
    
    try:
        with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
            tokens_data = json.load(f)
            
        # 转换过期时间字符串为datetime对象
        TOKENS = {}
        for token, data in tokens_data.items():
            if "expiry" in data:
                data["expiry"] = datetime.fromisoformat(data["expiry"])
                TOKENS[token] = data
        logging.info(f"成功加载了 {len(TOKENS)} 个令牌")
    except Exception as e:
        logging.error(f"加载令牌数据失败: {str(e)}")
        TOKENS = {}

def save_tokens():
    """保存令牌数据到文件"""
    try:
        # 创建临时数据结构，将datetime转换为ISO格式字符串
        tokens_to_save = {}
        for token, data in TOKENS.items():
            token_data = data.copy()
            if isinstance(token_data["expiry"], datetime):
                token_data["expiry"] = token_data["expiry"].isoformat()
            tokens_to_save[token] = token_data
            
        # 保存到临时文件，然后重命名，确保原子性写入
        temp_file = f"{TOKENS_FILE}.tmp"
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(tokens_to_save, f, ensure_ascii=False, indent=2)
                
            # 在Windows上，可能需要先删除目标文件
            if os.path.exists(TOKENS_FILE):
                try:
                    os.remove(TOKENS_FILE)
                except PermissionError:
                    logging.warning(f"无法删除目标文件 {TOKENS_FILE}，可能正在被其他进程使用")
                    # 在Windows上可能需要等待一下
                    time.sleep(0.1)
                    os.remove(TOKENS_FILE)
                
            os.rename(temp_file, TOKENS_FILE)
            logging.info(f"成功保存了 {len(TOKENS)} 个令牌到 {TOKENS_FILE}")
        except Exception as e:
            logging.error(f"保存令牌数据到临时文件或重命名失败: {str(e)}")
            # 尝试直接写入目标文件
            with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
                json.dump(tokens_to_save, f, ensure_ascii=False, indent=2)
            logging.info(f"通过直接写入方式成功保存了 {len(TOKENS)} 个令牌")
    except Exception as e:
        logging.error(f"保存令牌数据失败: {str(e)}", exc_info=True)

@app.route('/api/auth/refresh-token', methods=['POST'])
@require_auth
@require_token
def refresh_token():
    """刷新令牌接口"""
    try:
        # 从g对象中获取当前用户信息
        current_account = g.account
        current_device_code = g.device_code
        current_role = g.role
        client_ip = g.client_ip
        
        # 获取当前令牌
        auth_header = request.headers.get('Authorization')
        current_token = auth_header[7:]  # 去掉'Bearer '前缀
        
        # 生成新的令牌
        new_token = secrets.token_urlsafe(32)
        expiry_time = datetime.now() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
        
        # 存储新令牌
        TOKENS[new_token] = {
            "account": current_account,
            "expiry": expiry_time,
            "device_code": current_device_code,
            "role": current_role
        }
        
        # 删除旧令牌
        if current_token in TOKENS:
            del TOKENS[current_token]
            
        # 持久化保存令牌
        save_tokens()
        
        # 记录令牌刷新操作
        log_query(current_account, "token_refresh", {"account": current_account}, 1, client_ip)
        
        # 构建响应数据
        response_data = {
            "token": new_token,
            "expiry": expiry_time.isoformat(),
            "user": {
                "account": current_account,
                "role": current_role
            }
        }
        
        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except Exception as e:
        logging.error(f"刷新令牌失败: {str(e)}", exc_info=True)
        raise SecurityException("令牌刷新失败", 500)


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
@require_token
def handle_logout():
    """用户登出接口"""
    try:
        # 从g对象中获取当前用户信息
        current_account = g.account
        client_ip = g.client_ip
        
        # 获取当前令牌
        auth_header = request.headers.get('Authorization')
        current_token = auth_header[7:]  # 去掉'Bearer '前缀
        
        # 删除令牌
        if current_token in TOKENS:
            del TOKENS[current_token]
            # 持久化保存令牌
            save_tokens()
            
        # 记录登出操作
        log_query(current_account, "logout_success", {"account": current_account}, 1, client_ip)
        
        # 构建响应数据
        response_data = {
            "status": "success",
            "message": "登出成功"
        }
        
        # 加密响应数据
        response_data_bytes = json.dumps(response_data).encode('utf-8')
        iv = os.urandom(AES_IV_SIZE)
        encrypted_response_content = encrypt_data(response_data_bytes, g.aes_key, iv)
        full_response_body = iv + encrypted_response_content
        
        return jsonify({"data": base64.b64encode(full_response_body).decode('utf-8')})
        
    except Exception as e:
        logging.error(f"登出失败: {str(e)}", exc_info=True)
        raise SecurityException("登出失败", 500)

if __name__ == '__main__':
    # 加载RSA密钥
    load_or_generate_rsa_keys()
    
    # 加载黑名单IP
    load_blacklist_ips()
    
    # 加载令牌
    load_tokens()
    
    # 确保用户文件存在
    if not os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                pass  # 创建空文件
            logging.info(f"创建了新的用户文件 {USERS_FILE}")
        except Exception as e:
            logging.error(f"创建用户文件失败: {str(e)}")
    
    # 启动服务器
    app.run(debug=True, host='0.0.0.0', port=5000)
