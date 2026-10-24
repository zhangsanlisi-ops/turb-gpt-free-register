# -*- coding: utf-8 -*-
"""
RoxyBrowser 指纹浏览器自动化注册配置。

官方文档：
- API 默认 host: http://127.0.0.1:50000
- 所有接口请求头必须带 token
- 可配合 Selenium / Puppeteer / Playwright 自动化
"""
from config.env_loader import env_str, apply_env_overrides


# 注册驱动：
#   "protocol"     = 原有 curl_cffi 纯协议注册（容易封号，不建议）
#   "roxy"         = 调用 RoxyBrowser 指纹浏览器 + Selenium 自动化注册
#   "cloak"        = 调用 CloakBrowser + Playwright/Selenium 适配层注册
#   "browser_use"  = Browser Use Cloud stealth Chromium + Playwright
#   "skyvern"      = Skyvern Browser Sessions + Playwright
REGISTRATION_DRIVER: str = "roxy"

# RoxyBrowser 本地 API
ROXY_API_BASE: str = "http://127.0.0.1:50100"
ROXY_API_TOKEN: str = env_str("ROXY_API_TOKEN", "")

# Roxy 环境/Profile ID；留空时使用 ROXY_PROFILE_CREATE_* 先创建临时环境（如果接口支持）
ROXY_PROFILE_ID: str = ""

# Roxy 工作区 ID。Roxy 创建 Profile 时接口要求 workspaceId，必须填写。
# 可在 Roxy 工作区/团队页面或 API 返回中查看。
ROXY_WORKSPACE_ID: str = "90143"

# Roxy 项目 ID。/browser/workspace 返回 project_details.projectId；创建 Profile 时一并提交。
ROXY_PROJECT_ID: str = "97471"

# 获取团队/工作区列表接口路径。不同版本若不同，可在 WebUI 修改；客户端也会自动尝试多个常见路径。
ROXY_WORKSPACE_LIST_PATH: str = "/browser/workspace"
ROXY_WORKSPACE_LIST_METHOD: str = "GET"

# 接口路径模板。不同版本如有差异，只改这里即可。
# {profile_id} 会替换为 ROXY_PROFILE_ID。
ROXY_OPEN_PATH: str = "/browser/open"
ROXY_CLOSE_PATH: str = "/browser/close"
ROXY_CREATE_PATH: str = "/browser/create"

# 接口方法：常见 open/close 为 GET；若你的版本要求 POST，可在 WebUI/配置里改。
ROXY_OPEN_METHOD: str = "POST"
ROXY_CLOSE_METHOD: str = "POST"
ROXY_CREATE_METHOD: str = "POST"

# 打开浏览器时是否无头启动：
#   False = 显示 Roxy 浏览器窗口（便于观察/调试）
#   True  = 无头启动，不显示窗口（如果当前 Roxy 版本支持 headless）
ROXY_OPEN_HEADLESS: bool = False

# 打开浏览器时附加参数；会合并到 /browser/open 请求体，优先级高于默认值。
ROXY_OPEN_EXTRA_PARAMS: dict = {}

# Selenium 行为
ROXY_SELENIUM_TIMEOUT: int = 90
ROXY_KEEP_BROWSER_OPEN: bool = False
# 官方 Roxy 本地 API / RoxyChrome 临时环境并发创建、打开时容易串到匿名首页壳
# 或旧账号态，导致重复加载 ChatGPT 首页资源，单号流量从约 9-11 MiB 变成
# 18-24 MiB。默认不把整个注册串行化；只把“创建/打开/首屏登录页稳定”
# 这一小段加锁，后续 OTP 等待和资料页仍可多账号并发。
ROXY_SERIALIZE_REGISTRATION: bool = False
ROXY_SERIALIZE_STARTUP: bool = True

# 邮箱页推进：UI 提交后若仍停在 chatgpt.com 首页，不必傻等完整 Selenium 超时。
# 短暂等待后会走一次同一浏览器上下文的认证回退；数值可由 .env/WebUI 热加载调整。
ROXY_EMAIL_TRANSITION_TIMEOUT: int = 18
ROXY_EMAIL_UI_STALL_SECONDS: int = 5
ROXY_EMAIL_SUBMIT_ATTEMPTS: int = 3
# 邮箱 OTP 最大重发/重取轮数。过高会在“OpenAI 未投递验证码”的邮箱上空等，
# 同时让浏览器保持活跃持续消耗流量。
ROXY_OTP_MAX_ATTEMPTS: int = 2

# OpenAI 可能在邮箱后先给 OTP，再提供“使用密码继续”链接。默认尊重已经进入的
# OTP 路径，避免 OTP -> 密码 -> OTP 的回跳；只有明确需要落库密码时才开启。
ROXY_PREFER_PASSWORD_SIGNUP: bool = False

# Roxy API transient 错误重试。create 接口默认不重试，避免超时后重复创建孤儿环境；
# 仅 TCP connection-refused（请求尚未送达）会使用该次数重试，open/close/delete 也会重试。
ROXY_API_RETRIES: int = 3
ROXY_API_RETRY_DELAY: int = 2

# 环境生命周期：
#   True  = 一号一环境：每个账号强制创建新 Profile，用完关闭并删除，不允许复用 ROXY_PROFILE_ID
#   False = 可复用 ROXY_PROFILE_ID 或只关闭不删除
ROXY_ONE_PROFILE_PER_ACCOUNT: bool = True

# 一号一环境结束后是否删除 Profile。建议保持 True。
ROXY_DELETE_PROFILE_AFTER_RUN: bool = True

# 删除环境接口路径/方法；如你的 Roxy 版本不同，只改这里。
ROXY_DELETE_PATH: str = "/browser/delete"
ROXY_DELETE_METHOD: str = "POST"

# 创建 Roxy 环境时随机系统指纹；开启后每次 /browser/create 在 Windows / macOS 里随机选一个，
# 避免固定 macOS 指纹。
ROXY_RANDOM_OS_ON_CREATE: bool = True
ROXY_RANDOM_OS_CHOICES: str = "Windows,macOS"

# 创建 Roxy 环境时随机名称；开启后会覆盖 ROXY_PROFILE_CREATE_PAYLOAD 里的固定 name。
ROXY_RANDOM_PROFILE_NAME_ON_CREATE: bool = True
ROXY_PROFILE_NAME_PREFIX: str = "rb"

# 创建 Roxy 环境时默认系统指纹。仅在 ROXY_RANDOM_OS_ON_CREATE=False 时使用。
# Roxy 官方 os 枚举：Windows / macOS / Linux / IOS / Android。
ROXY_DEFAULT_OS: str = "macOS"
# 留空则使用 Roxy 对应系统的默认/最大版本；如需固定可填 15.3.2、14.7 等。
ROXY_DEFAULT_OS_VERSION: str = ""

# 创建 Roxy 环境时是否使用 config/proxy.py 的 PROXY_POOL：
#   False = 不主动给 Roxy 环境设置代理
#   True  = 每次创建环境时从 PROXY_POOL 随机取一个代理写入 proxyInfo
ROXY_CREATE_USE_PROXY_POOL: bool = False

# Roxy 代理检测通道；留空则不传 checkChannel。
ROXY_PROXY_CHECK_CHANNEL: str = "IP-API"
# 代理池里 host:port:user:pass 这种智能识别格式，按 Roxy 创建窗口的代理类型解析。
ROXY_PROXY_POOL_DEFAULT_SCHEME: str = "socks5"
# 从代理池创建时避免重复使用同一个代理账号/sid。会优先排除当前进程已预留、
# 以及历史成功账号里已保存到 proxy_used 的代理；代理池耗尽时才回退全池。
ROXY_PROXY_POOL_NO_REUSE: bool = True

# 官方 Roxy 的住宅/1024 代理并不是让内核直连外部代理，而是先通过 roxynet 注册映射：
#   POST http://127.0.0.1:<ROXY_ROXYNET_HTTP_PORT>/set_proxy {token: {addr,user_name,password,protocal}}
#   浏览器实际使用 socks5://token:token@127.0.0.1:<ROXY_ROXYNET_PROXY_PORT>
# 这与手动创建窗口里“测试代理 IP”的行为一致。
ROXY_USE_OFFICIAL_ROXYNET_PROXY: bool = True
ROXY_ROXYNET_HTTP_PORT: int = 50276
ROXY_ROXYNET_PROXY_PORT: int = 50274

# roxy-unlimited 直启 RoxyChrome 时不会自动启动官方 roxynet 链式代理。
# 对 1024proxy 这类在原版 Roxy 中依赖 "目标代理 -> 本地上游代理" 的线路，
# 启用后会自动启动本地 HTTP CONNECT 端口，并把 Roxy profile 代理改写为 http://127.0.0.1:<port>。
ROXY_PROXY_CHAIN_ENABLED: bool = False
# 仅当代理看起来是 1024proxy 时自动链式转发；避免影响普通 http/socks 代理。
ROXY_PROXY_CHAIN_ONLY_1024: bool = True
# 原版 Roxy 日志显示 1024proxy 经本机 127.0.0.1:7897 链接外网。
ROXY_PROXY_CHAIN_UPSTREAM: str = "http://127.0.0.1:7897"
ROXY_PROXY_CHAIN_BASE_PORT: int = 18100
ROXY_PROXY_CHAIN_MAX_PORTS: int = 300
# 创建 Roxy 环境前先用 CONNECT 预检本地链式代理。
# 1024proxy 目标代理或本机上游异常时，Chrome 会直接报 ERR_TUNNEL_CONNECTION_FAILED；
# 预检失败时默认不再回退到本地上游代理，否则会把真实代理池静默变成 127.0.0.1:7897。
ROXY_PROXY_CHAIN_PREFLIGHT: bool = True
ROXY_PROXY_CHAIN_FALLBACK_TO_UPSTREAM: bool = False
# 从代理池创建 Roxy 环境时最多尝试多少个代理；0/空表示遍历整池。
ROXY_PROXY_POOL_CREATE_MAX_ATTEMPTS: int = 0
# 没有 ROXY_PROFILE_ID 时创建环境的最小 payload；按你的 Roxy 版本字段调整。
# 默认开启 ROXY_RANDOM_PROFILE_NAME_ON_CREATE，因此这里的 name 只是兜底值。
ROXY_PROFILE_CREATE_PAYLOAD: dict = {
    "name": "gpt-free-register",
    "os": "macOS",
}


# Roxy Codex 授权等待 callback 的最长秒数
ROXY_CODEX_CALLBACK_TIMEOUT: int = 180

# 实验性：资料页提交前拦截 ChatGPT 主站 CDN JS/CSS，仅用原生 fetch 读取 session。
# 失败会撤销拦截并按旧流程重试；默认关闭。
ROXY_POST_AUTH_ASSET_SKIP: bool = False

# ---- .env overrides for WebUI editable fields ----
apply_env_overrides(globals(), {'REGISTRATION_DRIVER': 'str', 'ROXY_API_BASE': 'str', 'ROXY_API_TOKEN': 'str', 'ROXY_PROFILE_ID': 'str', 'ROXY_WORKSPACE_ID': 'str', 'ROXY_PROJECT_ID': 'str', 'ROXY_WORKSPACE_LIST_PATH': 'str', 'ROXY_OPEN_PATH': 'str', 'ROXY_OPEN_HEADLESS': 'bool', 'ROXY_CLOSE_PATH': 'str', 'ROXY_KEEP_BROWSER_OPEN': 'bool', 'ROXY_SERIALIZE_REGISTRATION': 'bool', 'ROXY_SERIALIZE_STARTUP': 'bool', 'ROXY_EMAIL_TRANSITION_TIMEOUT': 'int', 'ROXY_EMAIL_UI_STALL_SECONDS': 'int', 'ROXY_EMAIL_SUBMIT_ATTEMPTS': 'int', 'ROXY_OTP_MAX_ATTEMPTS': 'int', 'ROXY_PREFER_PASSWORD_SIGNUP': 'bool', 'ROXY_ONE_PROFILE_PER_ACCOUNT': 'bool', 'ROXY_DELETE_PROFILE_AFTER_RUN': 'bool', 'ROXY_RANDOM_OS_ON_CREATE': 'bool', 'ROXY_RANDOM_OS_CHOICES': 'str', 'ROXY_RANDOM_PROFILE_NAME_ON_CREATE': 'bool', 'ROXY_PROFILE_NAME_PREFIX': 'str', 'ROXY_CREATE_USE_PROXY_POOL': 'bool', 'ROXY_PROXY_CHECK_CHANNEL': 'str', 'ROXY_PROXY_POOL_DEFAULT_SCHEME': 'str', 'ROXY_PROXY_POOL_NO_REUSE': 'bool', 'ROXY_USE_OFFICIAL_ROXYNET_PROXY': 'bool', 'ROXY_ROXYNET_HTTP_PORT': 'int', 'ROXY_ROXYNET_PROXY_PORT': 'int', 'ROXY_PROXY_CHAIN_ENABLED': 'bool', 'ROXY_PROXY_CHAIN_ONLY_1024': 'bool', 'ROXY_PROXY_CHAIN_UPSTREAM': 'str', 'ROXY_PROXY_CHAIN_BASE_PORT': 'int', 'ROXY_PROXY_CHAIN_MAX_PORTS': 'int', 'ROXY_PROXY_CHAIN_PREFLIGHT': 'bool', 'ROXY_PROXY_CHAIN_FALLBACK_TO_UPSTREAM': 'bool', 'ROXY_PROXY_POOL_CREATE_MAX_ATTEMPTS': 'int', 'ROXY_DELETE_PATH': 'str', 'ROXY_CODEX_CALLBACK_TIMEOUT': 'int', 'ROXY_POST_AUTH_ASSET_SKIP': 'bool'})

