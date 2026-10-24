# -*- coding: utf-8 -*-
"""Im-Run Browser 本地 Open API 配置。"""
from config.env_loader import apply_env_overrides, env_str

IMRUN_API_BASE: str = "http://127.0.0.1:20081/open-api"
IMRUN_API_KEY: str = env_str("IMRUN_API_KEY", "")

# 指定环境时始终使用该环境；留空会选择本地第一个 Profile，列表为空时创建一个。
IMRUN_PROFILE_ID: str = ""
IMRUN_PROFILE_NAME_PREFIX: str = "imrun-register"
IMRUN_START_URL: str = "https://chatgpt.com/auth/login"
IMRUN_API_TIMEOUT: int = 90
# 首次页面导航发生 TLS/代理错误时，创建新 Profile（换代理）重试次数。
IMRUN_NAVIGATION_RETRIES: int = 2
# OTP/资料页完成后等待 ChatGPT 登录态同步的最长秒数。
IMRUN_SESSION_ACCESS_TOKEN_TIMEOUT: int = 90
# 资料页包含名字/生日控件动画；不能复用 Browser Use 的 28 秒快速上限。
IMRUN_PROFILE_TIMEOUT: int = 50
IMRUN_KEEP_BROWSER_OPEN: bool = False
# True 时向 Im-Run /start 传 headless=true；False 显示指纹浏览器窗口。
IMRUN_HEADLESS: bool = False
# False=只走邮箱 OTP；True=允许点击“使用密码继续”并创建账号密码。
IMRUN_PREFER_PASSWORD_SIGNUP: bool = False
# 旧配置：套餐查询已改为本地 RoxyBrowser，不再使用 Im-Run。保留字段仅兼容历史 .env。
IMRUN_PLAN_CHECK_FALLBACK: bool = False

# 与 Roxy 一致：每次注册新建独立 Profile，结束后 stop 并删除。
# 开启后忽略 IMRUN_PROFILE_ID；关闭后优先使用指定 ID，再回退到本地第一个 Profile。
IMRUN_ONE_PROFILE_PER_ACCOUNT: bool = True
IMRUN_DELETE_PROFILE_AFTER_RUN: bool = True

# 从本项目「代理池」随机取一条代理，写入 Im-Run ProfileDraft.proxy。
# Im-Run 的 /proxies 是其自身管理列表；这里直接写 Profile proxy，因此无需在 Im-Run 额外导入。
IMRUN_CREATE_USE_PROXY_POOL: bool = True
# 同一 WebUI 进程内优先不复用代理端点；池耗尽后自动开启下一轮。
IMRUN_PROXY_NO_REUSE: bool = True

apply_env_overrides(globals(), {
    "IMRUN_API_BASE": "str", "IMRUN_API_KEY": "str", "IMRUN_PROFILE_ID": "str",
    "IMRUN_PROFILE_NAME_PREFIX": "str", "IMRUN_START_URL": "str",
    "IMRUN_API_TIMEOUT": "int", "IMRUN_NAVIGATION_RETRIES": "int", "IMRUN_SESSION_ACCESS_TOKEN_TIMEOUT": "int", "IMRUN_PROFILE_TIMEOUT": "int", "IMRUN_KEEP_BROWSER_OPEN": "bool", "IMRUN_HEADLESS": "bool",
    "IMRUN_PREFER_PASSWORD_SIGNUP": "bool", "IMRUN_PLAN_CHECK_FALLBACK": "bool",
    "IMRUN_ONE_PROFILE_PER_ACCOUNT": "bool", "IMRUN_DELETE_PROFILE_AFTER_RUN": "bool",
    "IMRUN_CREATE_USE_PROXY_POOL": "bool", "IMRUN_PROXY_NO_REUSE": "bool",
})
