""" https://blog.linc.work/article/dfd1638c.html """

import logging
import json
from pathlib import Path

""" --- 基本配置 --- """

LOGGER_LEVEL=logging.DEBUG      # 日志级别（目前只有 DEBUG 级别日志）
# LOGGER_LEVEL=logging.INFO     # 日志级别（无 DEBUG 日志）
IS_VERIFY_SSL=True              # requests 库是否验证 SSL 证书，Charles 抓包用

""" -------------- """

import re
import sys
import os
from datetime import date, datetime
from playwright.sync_api import sync_playwright

if sys.platform == "win32":
    os.system("")

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import requests
from requests import Response
import base64


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
# Logger 配置
logger=logging.getLogger("MkuCheckInScript")
logger.setLevel(LOGGER_LEVEL)
logging_handler=logging.StreamHandler(sys.stdout)
logging_handler.setFormatter(ColoredFormatter())
logger.addHandler(logging_handler)

# RSA 公钥（用于密码加密）
RSA_KEY="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2g9Mhv3s+exdz7iV+M/oUheb8Tz3CCtMjXUBOmLxHzjEG6V0DcZGyNIwuIcPJeavRzdC+Hs01SneJ/5AZHQQVg66+vBdjBqahsv2Ibts9t6OOdg8YaVE8te26AQR3ISLxzERf62gEmO6Zgkl45unvt3BM4uy+60HXmuFC8i/jhKJW1Ax8gZddnjFs5Yx2fwHqx+8YTqd8kN3ovZaHSfwp31ioJwoYyPxZRlRDq0J+p3uQs/A8BcZm5yqPwWMCL18fleChin9Z3VX1VZfURYLnFHgpCqKWraU0z4WncB3MS9QEF+kYucCT+e9kpsrUhBlmpz1BZKjX/bI3qVcJw1CnQIDAQAB
-----END PUBLIC KEY-----"""

def encrypt_password(password: str) -> str:
    """使用 RSA 加密密码"""
    rsa_public_key = RSA.import_key(RSA_KEY)
    cipher_rsa = PKCS1_v1_5.new(rsa_public_key)
    encrypted_password_byte = cipher_rsa.encrypt(password.encode('utf-8'))
    return "__RSA__" + base64.b64encode(encrypted_password_byte).decode('utf-8')

# requests Session 配置
session=requests.Session()
session.headers.update({
    # "sec-ch-ua": '"Chromium";v="142", "Microsoft Edge";v="142", "Not_A Brand";v="99"',
    # "sec-ch-ua-mobile": "?0",
    # "sec-ch-ua-platform": "Windows",
    # "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
})
session.verify=IS_VERIFY_SSL
def response_hook(response: Response,*args,**kwargs):
    lines = response.text.splitlines()
    if len(lines) > 12:
        response_text = '\n'.join(lines[:12]) + f"\n<< more {len(lines) - 12} lines >>"
    else:
        response_text = '\n'.join(lines)
    logger.debug(f"Response from {response.url} [{response.status_code}] {response_text}")

session.hooks["response"]=response_hook

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

def select_account(accounts: list[dict]) -> dict:
    """显示账号列表，让用户选择"""
    print("\n请选择要打卡的账号：")
    for i, acc in enumerate(accounts, 1):
        print(f"  {i}. {acc['name']} ({acc['username']})")
    while True:
        try:
            choice = int(input("输入序号: "))
            if 1 <= choice <= len(accounts):
                return accounts[choice - 1]
            print(f"请输入 1-{len(accounts)} 之间的数字")
        except ValueError:
            print("请输入有效的数字")

def main():
    # 加载并选择账号
    accounts = load_accounts()
    account = select_account(accounts)
    username = account["username"]
    password_encoded = encrypt_password(account["password"])
    print(f"\n已选择账号: {account['name']} ({username})")

    """ 验证手机 """

    print("检测是否需要双因素验证... ",end='')
    resp_mfa_detect=session.post("https://cas.mku.edu.cn/cas/mfa/detect",
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
        resp_securephone=session.get("https://cas.mku.edu.cn/cas/mfa/initByType/securephone",
                    params={
                        "state": resp_mfa_detect_data["data"]["state"]
                    })
        resp_securephone_json=resp_securephone.json()
        gid=resp_securephone_json["data"]["gid"]
        phone_number=resp_securephone_json["data"]["securePhone"]
        is_want_to_send=get_choose(f"登录需要向 {phone_number} 发送短信验证码，是否继续？")
        if not is_want_to_send:
            print("用户取消发送验证码，结束登录")
            sys.exit(0)
        print("正在发送验证码...")
        resp_securephone_send=session.post("https://cas.mku.edu.cn/attest/api/guard/securephone/send",
                                           json={
                                               "gid":gid
                                           })
        while True:
            verify_code=input("输入收到的验证码：")
            resp_securephone_valid=session.post("https://cas.mku.edu.cn/attest/api/guard/securephone/valid",
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
    resp_web_page=session.get("https://cas.mku.edu.cn/cas/login")
    resp_web_page_html=resp_web_page.text
    try:
        execution = re.search(
                      r'name="execution" value="([^"]+)"', resp_web_page_html
                  ).group(1)
    except AttributeError:
        logger.error("无法从登录页面提取 execution")
        sys.exit(1)

    # 登录
    resp_login=session.post("https://cas.mku.edu.cn/cas/login",
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
        sys.exit(1)

    # 用户认证，让CAS系统自己带ticket进行302跳转到service指定服务（打卡服务）
    print("登录学工系统...")
    # resp_login_302=session.post("https://cas.mku.edu.cn/cas/login",
    #                         params={
    #                             "service":"https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_index.do"
    #                         },
    #                         allow_redirects=True)
    # 上下请求等效，下面这种请求会302至上面这种请求
    resp_login_302=session.post("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_index.do",
                            allow_redirects=True)

    print(f'获取到 JSESSIONID: {session.cookies.get("JSESSIONID",domain="xgyd.mku.edu.cn")}')
    # print(f'JSESSIONID: {session.cookies.get_dict()}')
    # 获取打卡需要的xsid
    print("获取 xsid...")
    resp_mrdk_edit=session.get("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_edit")
    resp_mrdk_edit_html=resp_mrdk_edit.text
    xsid = re.search(
                      r'id="xsid" value="([^"]+)"', resp_mrdk_edit_html
                  ).group(1)
    print(f"获取到 xsid: {xsid}")

    """ 打卡 """

    form_data = {
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
    resp_mrdk_save=session.post("https://xgyd.mku.edu.cn/acmc-weichat/wxapp/swkjjksb/mrdk_save.do",
                                data=form_data)
    resp_mrdk_save_data=resp_mrdk_save.json()
    if resp_mrdk_save_data["ret"]=="ok":
        print("打卡成功")
    elif resp_mrdk_save_data["ret"]=="more":
        print("重复打卡，今日已打卡")
    else:
        print(f"打卡接口返回未知结果：ret == {resp_mrdk_save_data['ret']}")

    print("正在截取打卡记录页面...")
    take_screenshot(session, output_dir="./screenshot/")

def take_screenshot(session: requests.Session, output_dir: str = ".") -> str | None:
    """
    使用 Playwright 截取打卡记录页面截图

    Args:
        session: 已登录的 requests Session 对象
        output_dir: 截图保存目录
    Returns:
        截图文件路径，失败返回 None
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_path = os.path.join(output_dir, f"screenshot_{timestamp}.png")

    # 转换 cookies 为 Playwright 格式
    playwright_cookies = []
    for cookie in session.cookies:
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
            context = browser.new_context(**p.devices["Pixel 5"])
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


if __name__ == "__main__":
    main()