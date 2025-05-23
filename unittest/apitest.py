import unittest
import os
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import requests

from main import AES_IV_SIZE


class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_url = "http://localhost:5000"
        cls.session = requests.Session()

        # 加载服务器真实密钥对（关键修改）
        try:
            # 从服务器文件加载私钥
            with open("D:\ldfmidleschool\openbox\server\private_key.pem", "rb") as f:
                cls.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )

            # 通过API获取服务器公钥（修改后的代码）
            response = cls.session.get(f"{cls.base_url}/api/auth/public-key")
            if response.status_code != 200:
                raise RuntimeError("获取公钥API失败")
            public_key_pem = response.json()["public_key"]
            cls.server_public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
        except Exception as e:
            raise RuntimeError(f"密钥加载失败: {str(e)}")

        # 生成合规设备码（128位HEX）
        cls.test_device_code = "e634aa92883bf41e9d2cab2961ba71a23f4b9c90423b729896e4c6b96f789fcca80f6242d399dfa88b9c4759c3a6f820fdcaf8362043594ec5d9209d95852fee"

        # 生成有效邀请码（使用服务器真实私钥）
        signature = cls.private_key.sign(
            cls.test_device_code.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        cls.test_invite_code = base64.b64encode(signature).decode('utf-8')

        # 初始化测试账户
        cls.test_account = "test_user"
        cls.test_password = "Test@Password123"  # 增强密码复杂度

        # 清理测试文件
        test_files = ["users.json", "query_records.json"]
        for f in test_files:
            if os.path.exists(f):
                os.remove(f)

    def setUp(self):
        # 每次测试前重置测试文件
        self.original_users_file = "users.json"
        self.original_query_file = "query_records.json"
        self.token = None

        # 使用测试专用的文件
        os.environ["USERS_FILE"] = "test_users.json"
        os.environ["QUERY_RECORDS_FILE"] = "test_query_records.json"

        # 确保文件存在
        open("test_users.json", "a").close()
        open("test_query_records.json", "a").close()

    def tearDown(self):
        # 恢复原始文件设置
        if hasattr(self, "original_users_file"):
            os.environ["USERS_FILE"] = self.original_users_file
        if hasattr(self, "original_query_file"):
            os.environ["QUERY_RECORDS_FILE"] = self.original_query_file

    def encrypt_request_data(self, data_dict):
        """加密请求数据"""
        # 生成随机的AES密钥和IV
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        # 序列化数据
        data_bytes = json.dumps(data_dict).encode('utf-8')

        # 加密数据
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data_bytes) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # 加密AES密钥
        encrypted_key = self.server_public_key.encrypt(
            base64.b64encode(aes_key),
            padding.PKCS1v15()
        )

        # 返回IV和加密数据的组合
        full_encrypted_body = iv + encrypted_data

        return {
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "encrypted_data": base64.b64encode(full_encrypted_body).decode('utf-8'),
            "aes_key": aes_key,
            "iv": iv
        }

    def decrypt_response_data(self, encrypted_response, aes_key):
        """
        解密服务器返回的加密响应数据

        参数:
            encrypted_response: 服务器返回的加密数据 (base64编码的字符串)
            aes_key: 用于解密的AES密钥 (原始字节)

        返回:
            解密后的字典数据
        """
        # Base64解码响应数据
        encrypted_bytes = base64.b64decode(encrypted_response)

        # 分离IV和加密数据 (IV是前16字节)
        iv = encrypted_bytes[:AES_IV_SIZE]
        encrypted_content = encrypted_bytes[AES_IV_SIZE:]

        # 解密数据
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_content) + decryptor.finalize()

        # 去除PKCS7填充
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        # 解析JSON
        return json.loads(decrypted_data.decode('utf-8'))

    def prepare_headers(self, path, method, encrypted_key, encrypted_data, aes_key):
        """准备请求头，包括签名"""
        nonce = hashlib.sha256(str(time.time()).encode()).hexdigest()
        timestamp = str(int(time.time() * 1000))

        # 构建签名字符串
        string_to_sign = f"{path}{method}{encrypted_data}{base64.b64encode(aes_key).decode('utf-8')}{nonce}{timestamp}"
        print(f"签名字符串: {string_to_sign}")  # 打印签名字符串
        signature = hashlib.sha256(string_to_sign.encode('utf-8')).hexdigest()

        return {
            "X-Encrypted-Key": encrypted_key,
            "X-Signature": signature,
            "X-Nonce": nonce,
            "X-Timestamp": timestamp,
            "X-Client-IP": "127.0.0.1",
            "Authorization": f"Bearer {self.token if self.token else ""}"
        }

    def test_public_key_endpoint(self):
        """测试公钥接口"""
        response = self.session.get(f"{self.base_url}/api/auth/public-key")
        self.assertEqual(response.status_code, 200)
        self.assertIn("public_key", response.json())
        self.assertTrue(response.json()["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))

    def test_verify_invite_valid(self):
        """测试有效的邀请码验证"""
        # 准备请求数据
        print(f"测试设备码: {self.test_device_code}, 测试邀请码: {self.test_invite_code}")
        request_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code
        }
        encrypted = self.encrypt_request_data(request_data)

        # 准备请求头和请求体
        headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted["encrypted_key"],
            encrypted_data=encrypted["encrypted_data"],
            aes_key=encrypted["aes_key"]
        )

        response = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("data", response.json())

    def test_verify_invite_invalid(self):
        """测试无效的邀请码验证"""
        # 使用错误的设备码
        request_data = {
            "device_code": "invalid_device_code",
            "invite_code": self.test_invite_code
        }
        encrypted = self.encrypt_request_data(request_data)

        headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted["encrypted_key"],
            encrypted_data=encrypted["encrypted_data"],
            aes_key=encrypted["aes_key"]
        )

        response = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )

        self.assertEqual(response.status_code, 400)

    def test_register_user(self):
        """测试用户注册"""
        # 先验证邀请码
        verify_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code
        }
        encrypted_verify = self.encrypt_request_data(verify_data)

        verify_headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted_verify["encrypted_key"],
            encrypted_data=encrypted_verify["encrypted_data"],
            aes_key=encrypted_verify["aes_key"]
        )

        verify_response = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=verify_headers,
            data=base64.b64decode(encrypted_verify["encrypted_data"])
        )
        self.assertEqual(verify_response.status_code, 200)

        # 注册新用户
        register_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code,
            "account": self.test_account,
            "password": self.test_password
        }
        encrypted_register = self.encrypt_request_data(register_data)

        register_headers = self.prepare_headers(
            path="/api/auth/register",
            method="POST",
            encrypted_key=encrypted_register["encrypted_key"],
            encrypted_data=encrypted_register["encrypted_data"],
            aes_key=encrypted_register["aes_key"]
        )

        register_response = self.session.post(
            f"{self.base_url}/api/auth/register",
            headers=register_headers,
            data=base64.b64decode(encrypted_register["encrypted_data"])
        )

        self.assertEqual(register_response.status_code, 200)
        self.assertIn("data", register_response.json())

    def test_register_duplicate_user(self):
        """测试重复用户注册"""
        # 先注册一个用户
        self.test_register_user()

        # 尝试再次注册相同用户
        register_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code,
            "account": self.test_account,
            "password": self.test_password
        }
        encrypted_register = self.encrypt_request_data(register_data)

        register_headers = self.prepare_headers(
            path="/api/auth/register",
            method="POST",
            encrypted_key=encrypted_register["encrypted_key"],
            encrypted_data=encrypted_register["encrypted_data"],
            aes_key=encrypted_register["aes_key"]
        )

        register_response = self.session.post(
            f"{self.base_url}/api/auth/register",
            headers=register_headers,
            data=base64.b64decode(encrypted_register["encrypted_data"])
        )

        self.assertEqual(register_response.status_code, 409)

    def test_login_success(self):
        """测试成功登录"""
        # 先注册用户


        # 登录
        login_data = {
            "account": self.test_account,
            "password": self.test_password,
            "device_code": self.test_device_code
        }
        encrypted_login = self.encrypt_request_data(login_data)

        login_headers = self.prepare_headers(
            path="/api/auth/login",
            method="POST",
            encrypted_key=encrypted_login["encrypted_key"],
            encrypted_data=encrypted_login["encrypted_data"],
            aes_key=encrypted_login["aes_key"]
        )

        login_response = self.session.post(
            f"{self.base_url}/api/auth/login",
            headers=login_headers,
            data=base64.b64decode(encrypted_login["encrypted_data"])
        )

        self.assertEqual(login_response.status_code, 200)
        self.assertIn("data", login_response.json())

    def test_login_wrong_password(self):
        """测试密码错误登录"""
        # 先注册用户


        # 使用错误密码登录
        login_data = {
            "account": self.test_account,
            "password": "wrong_password",
            "device_code": self.test_device_code
        }
        encrypted_login = self.encrypt_request_data(login_data)

        login_headers = self.prepare_headers(
            path="/api/auth/login",
            method="POST",
            encrypted_key=encrypted_login["encrypted_key"],
            encrypted_data=encrypted_login["encrypted_data"],
            aes_key=encrypted_login["aes_key"]
        )

        login_response = self.session.post(
            f"{self.base_url}/api/auth/login",
            headers=login_headers,
            data=base64.b64decode(encrypted_login["encrypted_data"])
        )

        self.assertEqual(login_response.status_code, 401)

    def test_login_wrong_device(self):
        """测试设备不匹配登录"""
        # 先注册用户


        # 使用错误设备码登录
        login_data = {
            "account": self.test_account,
            "password": self.test_password,
            "device_code": "wrong_device_code"
        }
        encrypted_login = self.encrypt_request_data(login_data)

        login_headers = self.prepare_headers(
            path="/api/auth/login",
            method="POST",
            encrypted_key=encrypted_login["encrypted_key"],
            encrypted_data=encrypted_login["encrypted_data"],
            aes_key=encrypted_login["aes_key"]
        )

        login_response = self.session.post(
            f"{self.base_url}/api/auth/login",
            headers=login_headers,
            data=base64.b64decode(encrypted_login["encrypted_data"])
        )

        self.assertEqual(login_response.status_code, 403)

    def test_query_students(self):
        """测试查询学生信息"""
        # 先注册并登录用户

        login_data = {
            "account": self.test_account,
            "password": self.test_password,
            "device_code": self.test_device_code
        }
        encrypted_login = self.encrypt_request_data(login_data)

        login_headers = self.prepare_headers(
            path="/api/auth/login",
            method="POST",
            encrypted_key=encrypted_login["encrypted_key"],
            encrypted_data=encrypted_login["encrypted_data"],
            aes_key=encrypted_login["aes_key"]
        )

        login_response = self.session.post(
            f"{self.base_url}/api/auth/login",
            headers=login_headers,
            data=base64.b64decode(encrypted_login["encrypted_data"])
        )
        self.assertEqual(login_response.status_code, 200)
        # 解密响应数据
        response_data = self.decrypt_response_data(
            login_response.json()["data"],
            encrypted_login["aes_key"]  # 使用请求时的AES密钥解密
        )
        self.token = response_data.get("token")

        print(response_data)

        # 获取登录后的AES密钥（实际应用中应从登录响应中获取）
        # 这里简化处理，使用注册时的AES密钥
        query_data = 'name=张三'
        encrypted_query = self.encrypt_request_data(query_data)

        query_headers = self.prepare_headers(
            path="/api/students",
            method="GET",
            encrypted_key=encrypted_query["encrypted_key"],
            encrypted_data=query_data,
            aes_key=encrypted_query["aes_key"]
        )

        # GET请求使用params传递查询参数
        response = self.session.get(
            f"{self.base_url}/api/students",
            headers=query_headers,
            params={"name": "张三"}
        )

        decrypted_response = self.decrypt_response_data(
            response.json()["data"],
            encrypted_query["aes_key"]
        )
        print(decrypted_response)

        self.assertEqual(response.status_code, 200)
        self.assertIn("data", response.json())

    def test_query_students_unauthorized(self):
        """测试未授权查询学生信息"""
        # 不登录直接查询
        query_data = 'name=张三'
        encrypted_query = self.encrypt_request_data(query_data)

        query_headers = self.prepare_headers(
            path="/api/students",
            method="GET",
            encrypted_key=encrypted_query["encrypted_key"],
            encrypted_data=query_data,
            aes_key=encrypted_query["aes_key"]
        )

        response = self.session.get(
            f"{self.base_url}/api/students",
            headers=query_headers,
            params={"name": "张三"}
        )

        # 应该返回401未授权
        self.assertEqual(response.status_code, 401)

    def test_replay_attack_protection(self):
        """测试重放攻击防护"""
        # 准备有效的请求数据
        request_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code
        }
        encrypted = self.encrypt_request_data(request_data)

        # 准备请求头和请求体
        headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted["encrypted_key"],
            encrypted_data=encrypted["encrypted_data"],
            aes_key=encrypted["aes_key"]
        )

        # 第一次请求应该成功
        response1 = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )
        self.assertEqual(response1.status_code, 200)

        # 使用相同的nonce和签名再次请求应该失败
        response2 = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )
        self.assertEqual(response2.status_code, 401)

    def test_invalid_signature(self):
        """测试无效签名"""
        # 准备请求数据
        request_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code
        }
        encrypted = self.encrypt_request_data(request_data)

        # 准备请求头，但修改签名
        headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted["encrypted_key"],
            encrypted_data=encrypted["encrypted_data"],
            aes_key=encrypted["aes_key"]
        )
        headers["X-Signature"] = "invalid_signature"

        response = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )

        self.assertEqual(response.status_code, 401)

    def test_expired_timestamp(self):
        """测试过期时间戳"""
        # 准备请求数据
        request_data = {
            "device_code": self.test_device_code,
            "invite_code": self.test_invite_code
        }
        encrypted = self.encrypt_request_data(request_data)

        # 准备请求头，但使用过期的时间戳
        headers = self.prepare_headers(
            path="/api/verify_invite",
            method="POST",
            encrypted_key=encrypted["encrypted_key"],
            encrypted_data=encrypted["encrypted_data"],
            aes_key=encrypted["aes_key"]
        )
        headers["X-Timestamp"] = str(int(time.time() * 1000) - 11000)  # 11秒前（超过10秒窗口）

        response = self.session.post(
            f"{self.base_url}/api/verify_invite",
            headers=headers,
            data=base64.b64decode(encrypted["encrypted_data"])
        )

        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()