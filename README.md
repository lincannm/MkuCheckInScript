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

编辑脚本开头配置用户名和密码：

```python
USERNAME="xxx"
PASSWORD="xxx"
```

最后直接运行，不必多说。