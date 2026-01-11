对MKU的学工系统晚打卡API进行逆向，实现免定位自动打卡。

功能：

- [x] 自动打卡
- [x] 自动截取打卡记录页面

# QuickStart

## 安装

### 1. 安装依赖

#### uv

本项目使用uv管理依赖。

```shell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
uv sync
```

#### pip

也可以用pip从requirements.txt安装依赖

```shell
pip install -r requirements.txt
```

### 2. 为Playwright安装浏览器（截图功能需要）

```shell
playwright install chromium
```

## 配置

首次运行会自动创建 `accounts.json` 配置文件，编辑该文件添加账号信息：

```json
{
  "accounts": [
    {
      "name": "显示名称",
      "username": "学号",
      "password": "密码"
    }
  ]
}
```

## 运行

```shell
python main.py
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `-d`, `--debug` | 启用调试日志输出 |
| `-c`, `--only-checkin` | 仅打卡，跳过截图 |
| `-s`, `--only-screenshot` | 仅截图打卡记录，跳过打卡 |
| `-o PATH`, `--output PATH` | 截图保存目录（默认：桌面） |

示例：

```shell
# 仅打卡，不截图
python main.py -c

# 仅截图，不打卡
python main.py -s

# 启用调试日志
python main.py -d

# 指定截图保存到当前目录
python main.py -o .
```