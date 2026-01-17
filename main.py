""" https://blog.linc.work/article/dfd1638c.html """

import logging
import json
import argparse
from pathlib import Path
import re
import sys
import os
import time
from datetime import date, datetime
from playwright.sync_api import sync_playwright
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import requests
from requests import Response
import base64

if sys.platform == "win32":
    os.system("")

""" 解析命令行参数 """

parser = argparse.ArgumentParser(description="MKU 学工系统自动打卡脚本")
parser.add_argument("-d", "--debug", action="store_true", help="启用调试日志输出")
parser.add_argument("-c", "--only-checkin", action="store_true", help="仅打卡")
parser.add_argument("-s", "--only-screenshot", action="store_true", help="仅截图打卡记录")
parser.add_argument("-o", "--output", type=str,
                    default=os.path.join(os.path.expanduser("~"), "Desktop"),
                    help="截图保存目录（默认：桌面）")
parser.add_argument("-m", "--manage-account", action="store_true", help="进入账号管理菜单")
args = parser.parse_args()

""" Logger 配置 """

class ColoredFormatter(logging.Formatter):
    """ 带颜色的日志格式化器 """
    # ANSI 颜色代码
    RESET="\033[0m"
    TIME_COLOR="\033[36m"  # 青色 - 时间
    LEVEL_COLORS={
        logging.DEBUG: "\033[34m",  # 蓝色
        logging.INFO: "\033[32m",  # 绿色
        logging.WARNING: "\033[33m",  # 黄色
        logging.ERROR: "\033[31m",  # 红色
        logging.CRITICAL: "\033[41m",  # 红色背景
    }
    def format(self,record):
        # 获取日志级别对应的颜色
        level_color=self.LEVEL_COLORS.get(record.levelno,self.RESET)
        # 格式化时间
        time_str=self.formatTime(record,self.datefmt)
        colored_time=f"{self.TIME_COLOR}{time_str}{self.RESET}"
        # 格式化日志级别
        colored_level=f"{level_color}{record.levelname}{self.RESET}"
        return f"{colored_level} - {colored_time}: {record.getMessage()}"
logger=logging.getLogger("MkuCheckInScript")
logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
logging_handler=logging.StreamHandler(sys.stdout)
logging_handler.setFormatter(ColoredFormatter())
logger.addHandler(logging_handler)

""" Session 配置 """

SESSION=requests.Session()
SESSION.headers.update({
    # "sec-ch-ua": '"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"',
    # "sec-ch-ua-mobile": "?0",
    # "sec-ch-ua-platform": "Windows",
    # "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
})
SESSION.verify=True
def response_hook(response: Response,*args,**kwargs):
    lines = response.text.splitlines()
    if len(lines) > 12:
        response_text = '\n'.join(lines[:12]) + f"\n<< more {len(lines) - 12} lines >>"
    else:
        response_text = '\n'.join(lines)
    logger.debug(f"Response from {response.url} [{response.status_code}] {response_text}")
SESSION.hooks["response"]=response_hook

""" 账号管理交互 """

def get_choose(msg: str):
    while True:
        inp=input(f"{msg} (Y/n): ")
        if inp.lower()=='y' or inp=='':
            return True
        elif inp.lower()=='n':
            return False
        else:
            continue

def load_accounts() -> list[dict]:
    """从 accounts.json 加载账号列表"""
    config_path = Path(__file__).parent / "accounts.json"
    if not config_path.exists():
        # 首次运行时创建示例配置
        example_config = {
            "accounts": [
                {
                    "name": "示例用户",
                    "username": "your_username",
                    "password": "your_password"
                }
            ]
        }
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(example_config, f, ensure_ascii=False, indent=2)
        print(f"已创建配置文件: {config_path}")
        print("请编辑 accounts.json 添加你的账号信息后重新运行")
        sys.exit(0)
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)["accounts"]

def select_accounts(accounts: list[dict]) -> list[dict]:
    """显示账号列表，让用户选择（支持多选）"""
    print("\n请选择要打卡的账号：")
    for i, acc in enumerate(accounts, 1):
        print(f"  {i}. {acc['name']} ({acc['username']})")

    while True:
        try:
            user_input = input("输入序号（多个账号用空格分隔）: ").strip()

            # 检查空输入
            if not user_input:
                print("输入不能为空，请重新输入")
                continue

            # 分割输入并转换为整数
            choices = user_input.split()
            selected_indices = []

            for choice_str in choices:
                try:
                    choice = int(choice_str)
                    if 1 <= choice <= len(accounts):
                        selected_indices.append(choice)
                    else:
                        print(f"序号 {choice} 超出范围（1-{len(accounts)}），请重新输入")
                        selected_indices = []
                        break
                except ValueError:
                    print(f"输入格式错误：'{choice_str}' 不是有效的数字，请重新输入")
                    selected_indices = []
                    break

            # 如果所有输入都有效
            if selected_indices:
                # 去重并保持顺序
                unique_indices = list(dict.fromkeys(selected_indices))
                selected_accounts = [accounts[i - 1] for i in unique_indices]

                # 显示已选择的账号
                print(f"\n已选择 {len(selected_accounts)} 个账号：")
                for acc in selected_accounts:
                    print(f"  - {acc['name']} ({acc['username']})")

                return selected_accounts

        except Exception as e:
            print(f"发生错误：{e}，请重新输入")

def validate_account_data(name: str, username: str, password: str) -> tuple[bool, str]:
    """
    验证账号数据完整性

    Args:
        name: 显示名称
        username: 用户名（学号）
        password: 密码

    Returns:
        (is_valid, error_message): 验证结果和错误信息
    """
    # 检查显示名称
    if not name or not name.strip():
        return False, "显示名称不能为空"

    # 检查用户名
    if not username or not username.strip():
        return False, "用户名不能为空"

    # 检查密码（不去除空格，密码可能包含空格）
    if not password:
        return False, "密码不能为空"

    return True, ""

def check_duplicate(accounts: list[dict], name: str, username: str,
                   exclude_index: int = -1) -> tuple[bool, str]:
    """
    检查 name 和 username 是否重复

    Args:
        accounts: 账号列表
        name: 要检查的显示名称
        username: 要检查的用户名
        exclude_index: 编辑时排除当前账号的索引（-1 表示不排除）

    Returns:
        (has_duplicate, duplicate_info): 是否重复及重复信息
    """
    name_lower = name.strip().lower()
    username_lower = username.strip().lower()

    for i, acc in enumerate(accounts):
        # 编辑模式下排除当前账号
        if i == exclude_index:
            continue

        # 检查 name 重复（不区分大小写）
        if acc['name'].strip().lower() == name_lower:
            return True, f"显示名称 '{name.strip()}' 已存在"

        # 检查 username 重复（不区分大小写）
        if acc['username'].strip().lower() == username_lower:
            return True, f"用户名 '{username.strip()}' 已存在"

    return False, ""

def save_accounts(accounts: list[dict]) -> bool:
    """
    保存账号列表到 accounts.json

    Args:
        accounts: 账号列表

    Returns:
        是否保存成功
    """
    config_path = Path(__file__).parent / "accounts.json"
    try:
        config_data = {"accounts": accounts}
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)
        return True
    except IOError as e:
        print(f"保存失败: {e}")
        return False
    except Exception as e:
        print(f"未知错误: {e}")
        return False

def add_account_interactive():
    """交互式添加账号"""
    print("\n=== 添加新账号 ===")

    # 加载现有账号
    config_path = Path(__file__).parent / "accounts.json"
    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                accounts = json.load(f)["accounts"]
        except Exception as e:
            print(f"读取配置文件失败: {e}")
            return
    else:
        accounts = []

    # 输入账号信息
    while True:
        name = input("请输入显示名称: ").strip()
        username = input("请输入用户名（学号）: ").strip()
        password = input("请输入密码: ")

        # 验证数据完整性
        is_valid, error_msg = validate_account_data(name, username, password)
        if not is_valid:
            print(f"✗ {error_msg}")
            retry = input("是否重新输入？(Y/n): ")
            if retry.lower() == 'n':
                print("已取消添加账号")
                return
            continue

        # 检查重复
        has_duplicate, duplicate_msg = check_duplicate(accounts, name, username)
        if has_duplicate:
            print(f"✗ {duplicate_msg}")
            retry = input("是否重新输入？(Y/n): ")
            if retry.lower() == 'n':
                print("已取消添加账号")
                return
            continue

        # 添加账号
        new_account = {
            "name": name,
            "username": username,
            "password": password
        }
        accounts.append(new_account)

        # 保存到文件
        if save_accounts(accounts):
            print(f"\n✓ 账号添加成功！")
            print(f"  姓名: {name}")
            print(f"  用户名: {username}")
        else:
            print("✗ 保存失败，请检查文件权限")

        break

def delete_account_interactive():
    """交互式删除账号"""
    print("\n=== 删除账号 ===")

    # 加载账号列表
    try:
        accounts = load_accounts()
    except SystemExit:
        return

    if not accounts:
        print("暂无账号")
        return

    # 显示账号列表
    print("当前账号列表：")
    for i, acc in enumerate(accounts, 1):
        print(f"  {i}. {acc['name']} ({acc['username']})")

    # 选择要删除的账号
    while True:
        try:
            choice = input("\n请输入要删除的账号序号（输入 0 取消）: ")
            choice_num = int(choice)

            if choice_num == 0:
                print("已取消删除")
                return

            if 1 <= choice_num <= len(accounts):
                selected_account = accounts[choice_num - 1]
                break

            print(f"请输入 1-{len(accounts)} 之间的数字")
        except ValueError:
            print("请输入有效的数字")

    # 二次确认
    print(f"\n确认删除以下账号？")
    print(f"  姓名: {selected_account['name']}")
    print(f"  用户名: {selected_account['username']}")

    if not get_choose("确认删除"):
        print("已取消删除")
        return

    # 删除账号
    accounts.pop(choice_num - 1)

    # 保存到文件
    if save_accounts(accounts):
        print("\n✓ 账号已删除")
    else:
        print("✗ 保存失败，请检查文件权限")

def edit_account_interactive():
    """交互式编辑账号"""
    print("\n=== 编辑账号 ===")

    # 加载账号列表
    try:
        accounts = load_accounts()
    except SystemExit:
        return

    if not accounts:
        print("暂无账号")
        return

    # 显示账号列表
    print("当前账号列表：")
    for i, acc in enumerate(accounts, 1):
        print(f"  {i}. {acc['name']} ({acc['username']})")

    # 选择要编辑的账号
    while True:
        try:
            choice = input("\n请输入要编辑的账号序号（输入 0 取消）: ")
            choice_num = int(choice)

            if choice_num == 0:
                print("已取消编辑")
                return

            if 1 <= choice_num <= len(accounts):
                selected_index = choice_num - 1
                selected_account = accounts[selected_index]
                break

            print(f"请输入 1-{len(accounts)} 之间的数字")
        except ValueError:
            print("请输入有效的数字")

    # 显示当前信息
    print(f"\n当前信息：")
    print(f"  姓名: {selected_account['name']}")
    print(f"  用户名: {selected_account['username']}")
    print(f"  密码: {'*' * 6}")

    # 输入新信息
    while True:
        print("\n请输入新信息（回车保持不变）：")
        new_name = input(f"显示名称 [{selected_account['name']}]: ").strip()
        new_username = input(f"用户名 [{selected_account['username']}]: ").strip()
        new_password = input(f"密码 [保持不变]: ")

        # 使用原值或新值
        final_name = new_name if new_name else selected_account['name']
        final_username = new_username if new_username else selected_account['username']
        final_password = new_password if new_password else selected_account['password']

        # 验证数据完整性
        is_valid, error_msg = validate_account_data(final_name, final_username, final_password)
        if not is_valid:
            print(f"✗ {error_msg}")
            retry = input("是否重新输入？(Y/n): ")
            if retry.lower() == 'n':
                print("已取消编辑")
                return
            continue

        # 检查重复（排除当前账号）
        has_duplicate, duplicate_msg = check_duplicate(accounts, final_name, final_username, selected_index)
        if has_duplicate:
            print(f"✗ {duplicate_msg}")
            retry = input("是否重新输入？(Y/n): ")
            if retry.lower() == 'n':
                print("已取消编辑")
                return
            continue

        # 更新账号信息
        accounts[selected_index] = {
            "name": final_name,
            "username": final_username,
            "password": final_password
        }

        # 保存到文件
        if save_accounts(accounts):
            print(f"\n✓ 账号信息已更新")
        else:
            print("✗ 保存失败，请检查文件权限")

        break

def list_accounts_formatted():
    """格式化列出所有账号"""
    print("\n=== 账号列表 ===")

    # 加载账号列表
    try:
        accounts = load_accounts()
    except SystemExit:
        return

    if not accounts:
        print("暂无账号")
        return

    # 表头
    print(f"{'序号':<6}{'姓名':<12}{'用户名':<15}{'密码':<10}")
    print("-" * 50)

    # 账号列表
    for i, acc in enumerate(accounts, 1):
        name = acc['name']
        username = acc['username']
        password = acc['password']
        print(f"{i:<6}{name:<12}{username:<15}{password:<10}")

    print(f"\n共 {len(accounts)} 个账号")

def manage_account_menu():
    """账号管理菜单"""
    while True:
        print("\n" + "=" * 50)
        print("账号管理菜单")
        print("=" * 50)
        print("1. 列出所有账号")
        print("2. 添加新账号")
        print("3. 编辑账号")
        print("4. 删除账号")
        print("0. 返回/退出")
        print("=" * 50)

        choice = input("\n请选择操作: ").strip()

        if choice == '1':
            list_accounts_formatted()
        elif choice == '2':
            add_account_interactive()
        elif choice == '3':
            edit_account_interactive()
        elif choice == '4':
            delete_account_interactive()
        elif choice == '0':
            print("退出账号管理")
            break
        else:
            print("无效的选择，请输入 0-4")

""" 登录相关 """

def encrypt_password(password: str) -> str:
    """使用 RSA 加密密码"""
    # RSA 公钥（用于密码加密）
    rsa_key="""-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2g9Mhv3s+exdz7iV+M/oUheb8Tz3CCtMjXUBOmLxHzjEG6V0DcZGyNIwuIcPJeavRzdC+Hs01SneJ/5AZHQQVg66+vBdjBqahsv2Ibts9t6OOdg8YaVE8te26AQR3ISLxzERf62gEmO6Zgkl45unvt3BM4uy+60HXmuFC8i/jhKJW1Ax8gZddnjFs5Yx2fwHqx+8YTqd8kN3ovZaHSfwp31ioJwoYyPxZRlRDq0J+p3uQs/A8BcZm5yqPwWMCL18fleChin9Z3VX1VZfURYLnFHgpCqKWraU0z4WncB3MS9QEF+kYucCT+e9kpsrUhBlmpz1BZKjX/bI3qVcJw1CnQIDAQAB
    -----END PUBLIC KEY-----"""
    rsa_public_key=RSA.import_key(rsa_key)
    cipher_rsa=PKCS1_v1_5.new(rsa_public_key)
    encrypted_password_byte=cipher_rsa.encrypt(password.encode('utf-8'))
    return "__RSA__"+base64.b64encode(encrypted_password_byte).decode('utf-8')

def take_screenshot(name: str = "none", output_dir: str = ".") -> str | None:
    """
    使用 Playwright 截取打卡记录页面截图

    Args:
        name: 截图所属账号的名字
        output_dir: 截图保存目录
    Returns:
        截图文件路径，失败返回 None
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_path = os.path.join(output_dir, f"screenshot_{name}_{timestamp}.png")

    # 转换 cookies 为 Playwright 格式
    playwright_cookies = []
    for cookie in SESSION.cookies:
        pw_cookie = {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain if cookie.domain else ".mku.edu.cn",
            "path": cookie.path if cookie.path else "/",
        }
        if cookie.expires:
            pw_cookie["expires"] = cookie.expires
        if cookie.secure:
            pw_cookie["secure"] = True
        playwright_cookies.append(pw_cookie)
    logger.debug(f"Playwright cookies: {playwright_cookies}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(**p.devices["Pixel 7"])
            context.add_cookies(playwright_cookies)

            page = context.new_page()
            page.goto(
                "https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_index.do",
                wait_until="networkidle"
            )
            page.wait_for_timeout(1000)  # 等待渲染完成
            page.screenshot(path=screenshot_path, full_page=True)

            context.close()
            browser.close()

            print(f"截图已保存: {screenshot_path}")
            return screenshot_path

    except Exception as e:
        logger.error(f"截图失败: {e}")
        return None

def check_in():
    # 获取打卡需要的xsid
    print("获取 xsid...")
    resp_mrdk_edit=SESSION.get("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_edit")
    resp_mrdk_edit_html=resp_mrdk_edit.text
    xsid=re.search(
        r'id="xsid" value="([^"]+)"',resp_mrdk_edit_html
    ).group(1)
    print(f"获取到 xsid: {xsid}")
    form_data={
        "id": "",
        "xsid": xsid,
        "jd": 118.47673,
        "wd": 25.03694,
        "dqszd": 350583,
        "drsfzxid": 1,
        "sbrq": date.today().strftime('%Y-%m-%d'),
        "dqszdmc": "福建省泉州市南安市",
        "tw": 36.5,
        "dqszdxxdz": "康美校区",
        "ycms": "",
        "twid": 1,
        "jzkid": 1
    }
    logger.debug(f"form_data = {form_data}")
    is_want_to_sign=get_choose("是否要打卡？")
    if not is_want_to_sign:
        print("用户取消打卡，结束程序")
        sys.exit(0)
    resp_mrdk_save=SESSION.post("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_save.do",
                                data=form_data)
    resp_mrdk_save_data=resp_mrdk_save.json()
    if resp_mrdk_save_data["ret"] == "ok":
        print("打卡成功")
    elif resp_mrdk_save_data["ret"] == "more":
        print("重复打卡，今日已打卡")
    else:
        print(f"打卡接口返回未知结果：ret == {resp_mrdk_save_data['ret']}")

""" 处理单个账号的打卡和截图 """

def process_account(account: dict, args) -> bool:
    """
    处理单个账号的打卡和/或截图操作

    参数：
        account: 账号字典，包含 'name', 'username', 'password'
        args: 命令行参数对象

    返回：
        bool: 处理成功返回 True，失败返回 False
    """
    try:
        username = account["username"]
        password_encoded = encrypt_password(account["password"])
        print(f"\n已选择账号: {account['name']} ({username})")

        """ 验证手机 """

        print("检测是否需要双因素验证... ",end='')
        resp_mfa_detect=SESSION.post("https://cas.mku.edu.cn/cas/mfa/detect",
                                     data={
                                          'username': username,
                                          'password': password_encoded
                                      },
                                     headers={
                                          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                                      })
        resp_mfa_detect_data=resp_mfa_detect.json()
        print("是" if resp_mfa_detect_data["data"]["need"] else "否")

        # 如果需要手机验证码验证
        if resp_mfa_detect_data["data"]["need"]:
            resp_securephone=SESSION.get("https://cas.mku.edu.cn/cas/mfa/initByType/securephone",
                                         params={
                            "state": resp_mfa_detect_data["data"]["state"]
                        })
            resp_securephone_json=resp_securephone.json()
            gid=resp_securephone_json["data"]["gid"]
            phone_number=resp_securephone_json["data"]["securePhone"]
            is_want_to_send=get_choose(f"登录需要向 {phone_number} 发送短信验证码，是否继续？")
            if not is_want_to_send:
                print("用户取消发送验证码，跳过此账号")
                return False
            print("正在发送验证码...")
            resp_securephone_send=SESSION.post("https://cas.mku.edu.cn/attest/api/guard/securephone/send",
                                               json={
                                                   "gid":gid
                                               })
            while True:
                verify_code=input("输入收到的验证码：")
                resp_securephone_valid=SESSION.post("https://cas.mku.edu.cn/attest/api/guard/securephone/valid",
                                                    json={
                                                        "code":verify_code,
                                                        "gid":gid
                                                    })
                resp_securephone_valid_status=resp_securephone_valid.json()["data"]["status"]
                if resp_securephone_valid_status==3:
                    print("短信验证失败")
                    continue
                elif resp_securephone_valid_status==2:
                    print("短信验证成功")
                    break
                else:
                    print(f"未知错误，status == {resp_securephone_valid_status}")
                    continue

        """ 登录 """

        print("登录 CAS...")
        # 获取表单execution字段
        resp_web_page=SESSION.get("https://cas.mku.edu.cn/cas/login")
        resp_web_page_html=resp_web_page.text
        try:
            execution = re.search(
                          r'name="execution" value="([^"]+)"', resp_web_page_html
                      ).group(1)
        except AttributeError:
            logger.error("无法从登录页面提取 execution")
            return False

        # 登录
        resp_login=SESSION.post("https://cas.mku.edu.cn/cas/login",
                                data={
                                    "username": username,
                                    "password": password_encoded,
                                    "captcha": "",
                                    "currentMenu": "1",
                                    "failN": "-1",
                                    "mfaState": resp_mfa_detect_data["data"]["state"],
                                    "execution": execution,
                                    "_eventId": "submit",
                                    "geolocation": "",
                                    "fpVisitorId": "",
                                    "submit1": "Login1"
                                },
                                headers={
                                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                                })
        resp_login_status_code=resp_login.status_code
        if not resp_login_status_code == 200:
            print(f"登录失败，status_code=={resp_login_status_code}")
            if resp_login_status_code == 401:
                print("原因：用户名或密码错误")
            return False

        # 用户认证，让CAS系统自己带ticket进行302跳转到service指定服务（打卡服务）
        print("登录学工系统...")
        resp_mrdk_index=SESSION.post("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_index.do",
                                     allow_redirects=True)

        print(f'获取到 JSESSIONID: {SESSION.cookies.get("JSESSIONID",domain="xgyd.mku.edu.cn")}')

        """ 开始打卡 """

        if not args.only_screenshot:
            # 检查是否要打卡
            pattern=r'<div[^>]*foot_btn[^>]*>(.*?)</div>'
            dk_text=re.search(pattern,resp_mrdk_index.text).group(1)
            if dk_text == '上报':
                # 打卡
                check_in()
            else:
                print("无需打卡，因为已经打卡完毕")
        else:
            print("已跳过打卡步骤")

        if not args.only_checkin:
            print("正在截取打卡记录页面...")
            take_screenshot(name=account['name'],output_dir=args.output)
        else:
            print("已跳过截图步骤")

        return True

    except Exception as e:
        print(f"处理账号时发生错误：{e}")
        logger.exception("处理账号时发生异常")
        return False

""" 主函数 """

def main():
    # 检查是否为账号管理模式
    if args.manage_account:
        manage_account_menu()
        return

    # 加载并选择账号（支持多选）
    accounts = load_accounts()
    selected_accounts = select_accounts(accounts)

    # 显示将要处理的账号数量
    print(f"\n将为 {len(selected_accounts)} 个账号执行操作\n")

    # 批量处理账号
    results = []
    for idx, account in enumerate(selected_accounts, 1):
        print(f"{'='*50}")
        print(f"正在处理第 {idx}/{len(selected_accounts)} 个账号: {account['name']}")
        print(f"{'='*50}\n")

        # 处理单个账号
        success = process_account(account, args)
        results.append({
            'name': account['name'],
            'username': account['username'],
            'success': success
        })


    # 打印汇总结果
    print(f"\n{'='*50}")
    print("处理完成！汇总结果：")
    print(f"{'='*50}")
    for result in results:
        status = "✓ 成功" if result['success'] else "✗ 失败"
        print(f"{status} - {result['name']} ({result['username']})")


if __name__ == "__main__":
    main()