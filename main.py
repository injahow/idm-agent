# -*- coding: utf-8 -*-
import os
import sys
import time
import subprocess
from urllib.parse import urlparse, unquote
import webbrowser
import json
import hashlib
import secrets
import hmac
from threading import Thread
from flask import Flask, request, jsonify
# --- 日志配置 ---
import logging
from logging.handlers import TimedRotatingFileHandler
# --- GUI / 托盘依赖 ---
import pystray
from PIL import Image, ImageDraw
import tkinter as tk
from tkinter import messagebox, filedialog

# 获取程序所在目录
if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(os.path.abspath(__file__))

# 日志目录
log_dir = os.path.join(app_dir, "logs")
os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, "idm_agent.log")

# --- 日志配置 ---
logger = logging.getLogger("IDM-Agent")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = TimedRotatingFileHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8"
    )
    file_handler.suffix = "%Y-%m-%d"
    file_formatter = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # 控制台日志
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

# --- Windows 注册表（开机启动）---
try:
    import winreg as reg
except ImportError:
    reg = None

# --- 全局样式配置 ---
class StyleConfig:
    # 颜色方案
    PRIMARY_COLOR = "#4A6CF7"      # 主色调（蓝色）
    SECONDARY_COLOR = "#6C757D"    # 次要颜色（灰色）
    SUCCESS_COLOR = "#28A745"      # 成功色（绿色）
    DANGER_COLOR = "#DC3545"       # 危险色（红色）
    WARNING_COLOR = "#FFC107"      # 警告色（黄色）
    LIGHT_COLOR = "#F8F9FA"        # 浅色背景
    DARK_COLOR = "#343A40"         # 深色文字
    WHITE_COLOR = "#FFFFFF"        # 白色
    HOVER_COLOR = "#3A5CE7"        # 悬停色
    
    # 字体配置
    FONT_MAIN = ("Microsoft YaHei", 10)
    FONT_BOLD = ("Microsoft YaHei", 10, "bold")
    FONT_SMALL = ("Microsoft YaHei", 9)
    FONT_MONO = ("Consolas", 10)
    
    # 尺寸配置
    WINDOW_PADDING = 20
    ELEMENT_SPACING = 10
    BUTTON_PADDING = (20, 6)
    BORDER_RADIUS = 6
    SHADOW_EFFECT = 2

# --- 配置 ---
TIME_WINDOW_MS = 60 * 1000  # 60秒，单位：毫秒
CONFIG_FILE = os.path.join(app_dir, "idm_agent_config.json")
DEFAULT_CONFIG = {
    "secret_key": lambda: secrets.token_urlsafe(32),
    "idm_path": r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    "idm_auto_download": False
}

def load_config():
    """智能加载配置：差量合并，默认值填充"""
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                if isinstance(file_config, dict):
                    config.update(file_config)
                else:
                    logger.warning("配置文件格式错误，使用默认配置")
        except Exception as e:
            logger.warning(f"配置加载失败: {e}")
    for key, default_value in DEFAULT_CONFIG.items():
        if key not in config:
            config[key] = default_value() if callable(default_value) else default_value
    if not os.path.exists(CONFIG_FILE) or _config_needs_update(config):
        save_config(config)
    
    return config

def _config_needs_update(current_config):
    """检查配置是否需要更新"""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            saved_config = json.load(f)
        return any(
            key not in saved_config or saved_config[key] != current_config[key]
            for key in current_config.keys()
        )
    except:
        return True

def save_config(config):
    """保存配置"""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    safe_config = {}
    safe_config.update(config)
    for key, default_value in DEFAULT_CONFIG.items():
        if key not in safe_config:
            safe_config[key] = default_value() if callable(default_value) else default_value
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(safe_config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"配置保存失败: {e}")

config = load_config()

# --- Flask App ---
app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response

@app.route('/download', methods=['OPTIONS'])
def handle_options():
    return '', 200

def generate_md5_signature(params, secret):
    items = [(k, v) for k, v in params.items() if k != 'sign' and v is not None]
    items.sort(key=lambda x: x[0])
    raw = '&'.join(f"{k}={v}" for k, v in items) + secret
    return hashlib.md5(raw.encode('utf-8')).hexdigest()

def verify_md5_signature(params, signature):
    try:
        ts = int(params.get('ts', 0))
    except (ValueError, TypeError):
        logger.warning("ts 无效")
        return False
    
    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts) > TIME_WINDOW_MS:
        logger.warning("签名已过期")
        return False
    
    current_secret = config["secret_key"]
    expected_sig = generate_md5_signature(params, current_secret)
    return hmac.compare_digest(expected_sig, signature)

def is_url(url):
    try:
        urlparse(url)
        return True
    except Exception as e:
        logger.warning(f"无效的 URL: {url}, err: {e}", exc_info=True)
        return False

def truncate_filename_with_ext(name, max_length=255):
    """
    截断文件名至 max_length
    """
    if not isinstance(name, str) or not name:
        return ""
    if '.' in name and not name.startswith('.'):
        parts = name.rsplit('.', 1)
        basename, ext = parts[0], parts[1]
    else:
        basename, ext = name, ""
    if not ext:
        return basename[:max_length]
    max_basename_len = max_length - len(ext) - 1
    if max_basename_len <= 0:
        return ext[:max_length]
    truncated_basename = basename[:max_basename_len]
    result = f"{truncated_basename}.{ext}"
    return result

def sanitize_filename(name):
    bad_chars = '<>:"/\\|?*'
    for c in bad_chars:
        name = name.replace(c, '')
    name = name.lstrip('.')
    return truncate_filename_with_ext(name)

@app.route('/download', methods=['GET', 'POST'])
def add_download():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        params = {
            "url": data.get('url'),
            "filename": data.get('filename'),
            "ts": data.get('ts')
        }
        signature = data.get('sign')
    else:
        params = {
            "url": request.args.get('url'),
            "filename": request.args.get('filename'),
            "ts": request.args.get('ts')
        }
        signature = request.args.get('sign')

    if not all([params['url'], params['ts'], signature]):
        logger.warning("缺少必要参数: url, ts 或 sign")
        return jsonify({"error": "Missing required fields: url, ts, sign"}), 400

    if not verify_md5_signature(params, signature):
        logger.warning("签名验证失败或已过期")
        return jsonify({"error": "Invalid or expired signature"}), 403

    try:
        idm_exe = config["idm_path"]
        if not os.path.isfile(idm_exe):
            logger.error(f"IDM 未找到: {idm_exe}")
            return jsonify({"error": f"IDM 未找到: {idm_exe}"}), 500

        if not params['url'] or not is_url(params['url']):
            return jsonify({"error": "Invalid URL"}), 400
        
        url = unquote(params['url'])
        logger.info(f"合法请求: {url}")

        cmd = [idm_exe, "/d", url]
        if params['filename']:
            filename = unquote(params['filename'])
            filename = sanitize_filename(params['filename'])
            if filename:
                cmd.extend(["/f", filename])

        if config["idm_auto_download"]:
            cmd.append("/n")

        subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)
        return jsonify({"code": 0, "message": "Download sent to IDM"}), 200
    except Exception as e:
        logger.error(f"执行下载时发生异常: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>IDM Agent 运行中</title>
        <style>
            body { font-family: 'Microsoft YaHei', sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .container { background: #f8f9fa; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h2 { color: #4A6CF7; margin-bottom: 20px; }
            code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; color: #DC3545; }
            .param-box { background: white; padding: 15px; border-radius: 6px; margin: 15px 0; border-left: 4px solid #4A6CF7; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>IDM Agent 正在运行</h2>
            <p>接口地址: <code>http://127.0.0.1:16880/download</code></p>
            <div class="param-box">
                <p>必填参数:</p>
                <ul>
                    <li><code>url</code>: 下载链接</li>
                    <li><code>ts</code>: 毫秒时间戳</li>
                    <li><code>sign</code>: 签名值</li>
                </ul>
                <p>可选参数:</p>
                <ul>
                    <li><code>filename</code>: 文件名</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

# --- 工具函数 ---
def create_image():
    """创建托盘图标"""
    ICON_SIZE = (32, 32)
    BG_COLOR = (255, 255, 255)
    CROSS_COLOR = (74, 108, 247)  # 使用主色调
    LINE_WIDTH = 4
    PADDING = 2
    
    image = Image.new("RGB", ICON_SIZE, BG_COLOR)
    draw = ImageDraw.Draw(image)
    center_x = ICON_SIZE[0] / 2 - 0.5
    center_y = ICON_SIZE[1] / 2 - 0.5
    
    # 绘制十字线
    horizontal_start = (PADDING, center_y)
    horizontal_end = (ICON_SIZE[0] - PADDING, center_y)
    vertical_start = (center_x, PADDING)
    vertical_end = (center_x, ICON_SIZE[1] - PADDING)
    
    draw.line([horizontal_start, horizontal_end], fill=CROSS_COLOR, width=LINE_WIDTH, joint="round")
    draw.line([vertical_start, vertical_end], fill=CROSS_COLOR, width=LINE_WIDTH, joint="round")
    
    return image

def create_custom_window(title, width, height):
    """创建统一样式的窗口"""
    root = tk.Tk()
    root.title(title)
    root.geometry(f"{width}x{height}")
    root.resizable(False, False)
    root.configure(bg=StyleConfig.LIGHT_COLOR)
    
    # 设置窗口图标（如果有）
    try:
        root.iconphoto(False, tk.PhotoImage(data=create_image().tobytes()))
    except:
        pass
    
    # 居中显示
    root.withdraw()
    root.update_idletasks()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    root.geometry(f"{width}x{height}+{x}+{y}")
    root.deiconify()
    
    return root

def create_styled_button(parent, text, command, bg_color=StyleConfig.PRIMARY_COLOR, 
                        fg_color=StyleConfig.WHITE_COLOR, hover_color=StyleConfig.HOVER_COLOR):
    """创建样式统一的按钮"""
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        font=StyleConfig.FONT_MAIN,
        bg=bg_color,
        fg=fg_color,
        relief="flat",
        padx=StyleConfig.BUTTON_PADDING[0],
        pady=StyleConfig.BUTTON_PADDING[1],
        cursor="hand2"
    )
    
    # 添加悬停效果
    def on_enter(e):
        btn.config(bg=hover_color)
    
    def on_leave(e):
        btn.config(bg=bg_color)
    
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    
    # 圆角效果（模拟）
    try:
        btn.config(bd=0, highlightthickness=0)
    except:
        pass
    
    return btn

def show_custom_message(title, message, msg_type="info", parent=None):
    """统一的消息提示框"""
    if msg_type == "info":
        bg = StyleConfig.PRIMARY_COLOR
    elif msg_type == "warning":
        bg = StyleConfig.WARNING_COLOR
    elif msg_type == "error":
        bg = StyleConfig.DANGER_COLOR
    elif msg_type == "success":
        bg = StyleConfig.SUCCESS_COLOR
    else:
        bg = StyleConfig.PRIMARY_COLOR
    
    # 创建临时窗口用于样式
    temp_root = tk.Toplevel(parent) if parent else tk.Tk()
    temp_root.withdraw()
    temp_root.configure(bg=bg)
    
    # 显示消息框
    if msg_type == "success":
        result = messagebox.showinfo(title, message, parent=temp_root)
    elif msg_type == "warning":
        result = messagebox.showwarning(title, message, parent=temp_root)
    elif msg_type == "error":
        result = messagebox.showerror(title, message, parent=temp_root)
    elif msg_type == "question":
        result = messagebox.askyesno(title, message, parent=temp_root)
    else:
        result = messagebox.showinfo(title, message, parent=temp_root)
    
    temp_root.destroy()
    return result

# --- 注册表相关 ---
def is_autostart_enabled():
    if not reg:
        return False
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_READ)
        value, _ = reg.QueryValueEx(key, "IDM-Agent")
        reg.CloseKey(key)
        return os.path.abspath(sys.executable) in value
    except FileNotFoundError:
        return False

def set_autostart(enable=True):
    if not reg:
        show_custom_message("错误", "无法修改开机自启状态", "error")
        return
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_WRITE)
        exe_path = os.path.abspath(sys.executable)
        if enable:
            reg.SetValueEx(key, "IDM-Agent", 0, reg.REG_SZ, exe_path)
        else:
            try:
                reg.DeleteValue(key, "IDM-Agent")
            except FileNotFoundError:
                pass
        reg.CloseKey(key)
        logger.info(f"开机自启状态已{'启用' if enable else '禁用'}")
    except Exception as e:
        logger.error(f"修改开机自启失败: {e}")
        show_custom_message("错误", f"修改开机自启失败: {str(e)}", "error")

def is_idm_auto_download():
    return config["idm_auto_download"]
    
def set_idm_auto_download(enable=True):
    config["idm_auto_download"] = enable
    save_config(config)
    logger.info(f"IDM自动下载已{'启用' if enable else '禁用'}")

# --- 界面回调函数 ---
def show_secret_key(icon, item):
    """显示密钥窗口"""
    root = create_custom_window("安全密钥 - IDM Agent", 580, 240)
    
    # 警告提示框
    warning_frame = tk.Frame(root, bg=StyleConfig.LIGHT_COLOR)
    warning_frame.pack(pady=(15, 10), padx=StyleConfig.WINDOW_PADDING, fill="x")
    
    tk.Label(
        warning_frame,
        text="⚠️",
        font=("Arial", 16),
        fg=StyleConfig.DANGER_COLOR,
        bg=StyleConfig.LIGHT_COLOR
    ).pack(side=tk.LEFT)
    
    tk.Label(
        warning_frame,
        text="此密钥用于接口签名，请勿泄露给他人！",
        font=StyleConfig.FONT_BOLD,
        fg=StyleConfig.DANGER_COLOR,
        bg=StyleConfig.LIGHT_COLOR,
        anchor="w"
    ).pack(side=tk.LEFT, padx=(8, 0))
    
    # 密钥显示框
    key_frame = tk.Frame(root, bg=StyleConfig.LIGHT_COLOR)
    key_frame.pack(pady=StyleConfig.ELEMENT_SPACING, padx=StyleConfig.WINDOW_PADDING, fill="x")
    
    # 带边框的文本框
    key_text = tk.Text(
        key_frame,
        height=2,
        width=60,
        font=StyleConfig.FONT_MONO,
        bg=StyleConfig.WHITE_COLOR,
        fg=StyleConfig.DARK_COLOR,
        relief="solid",
        borderwidth=1,
        wrap="none"
    )
    key_text.insert("1.0", config["secret_key"])
    key_text.config(state="disabled")
    key_text.pack(fill="x", padx=0, pady=0)
    
    # 按钮区域
    btn_frame = tk.Frame(root, bg=StyleConfig.LIGHT_COLOR)
    btn_frame.pack(pady=StyleConfig.ELEMENT_SPACING)
    
    # 复制按钮
    def copy_key():
        root.clipboard_clear()
        root.clipboard_append(config["secret_key"])
        root.update()
        show_custom_message("成功", "密钥已复制到剪贴板", "success", root)

    copy_btn = create_styled_button(
        btn_frame,
        "复制密钥",
        copy_key,
        StyleConfig.PRIMARY_COLOR,
        StyleConfig.WHITE_COLOR,
        StyleConfig.HOVER_COLOR
    )
    copy_btn.pack(side=tk.LEFT, padx=10)
    
    # 关闭按钮
    close_btn = create_styled_button(
        btn_frame,
        "关闭",
        root.destroy,
        StyleConfig.PRIMARY_COLOR,
        StyleConfig.WHITE_COLOR,
        StyleConfig.HOVER_COLOR
    )
    close_btn.pack(side=tk.LEFT, padx=10)
    
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()

def set_idm_path(icon, item):
    """设置IDM路径窗口"""
    root = create_custom_window("设置 IDM 路径", 620, 180)
    
    # 标签
    label = tk.Label(
        root,
        text="请选择 IDM 主程序路径（IDMan.exe）：",
        bg=StyleConfig.LIGHT_COLOR,
        font=StyleConfig.FONT_MAIN
    )
    label.pack(pady=(15, 5), padx=StyleConfig.WINDOW_PADDING, anchor="w")
    
    # 路径输入框
    current_path = config.get("idm_path", "")
    path_var = tk.StringVar(value=current_path)
    
    path_frame = tk.Frame(root, bg=StyleConfig.LIGHT_COLOR)
    path_frame.pack(pady=5, padx=StyleConfig.WINDOW_PADDING, fill="x")
    
    path_entry = tk.Entry(
        path_frame,
        textvariable=path_var,
        font=StyleConfig.FONT_MONO,
        width=70,
        relief="solid",
        borderwidth=1
    )
    path_entry.pack(side=tk.LEFT, fill="x", expand=True)
    
    # 浏览按钮
    def browse_file():
        filepath = filedialog.askopenfilename(
            title="选择 IDMan.exe",
            filetypes=[("IDM 程序", "IDMan.exe"), ("可执行文件", "*.exe"), ("所有文件", "*.*")],
            initialdir=os.path.dirname(current_path) if current_path else "C:\\"
        )
        if filepath:
            path_var.set(filepath)
    
    browse_btn = create_styled_button(
        path_frame,
        "浏览...",
        browse_file,
        StyleConfig.PRIMARY_COLOR,
        StyleConfig.WHITE_COLOR,
        StyleConfig.HOVER_COLOR
    )
    browse_btn.pack(side=tk.RIGHT, padx=(10, 0))
    
    # 按钮区域
    btn_frame = tk.Frame(root, bg=StyleConfig.LIGHT_COLOR)
    btn_frame.pack(pady=StyleConfig.ELEMENT_SPACING)
    
    # 保存按钮
    def save_path():
        new_path = path_var.get().strip()
        if not new_path:
            show_custom_message("警告", "路径不能为空！", "warning", root)
            return
        if not new_path.endswith("IDMan.exe"):
            show_custom_message("警告", "路径应指向 IDMan.exe！", "warning", root)
            return
        if not os.path.isfile(new_path):
            show_custom_message("错误", "该文件不存在！", "error", root)
            return
        
        config["idm_path"] = new_path
        save_config(config)
        logger.info(f"IDM 路径已更新为: {new_path}")
        show_custom_message("成功", "IDM 路径已更新！", "success", root)
        root.destroy()
    
    save_btn = create_styled_button(
        btn_frame,
        "保存",
        save_path,
        StyleConfig.PRIMARY_COLOR,
        StyleConfig.WHITE_COLOR,
        StyleConfig.HOVER_COLOR
    )
    save_btn.pack(side=tk.LEFT, padx=10)
    
    # 取消按钮
    cancel_btn = create_styled_button(
        btn_frame,
        "✕ 取消",
        root.destroy,
        StyleConfig.PRIMARY_COLOR,
        StyleConfig.WHITE_COLOR,
        StyleConfig.HOVER_COLOR
    )
    cancel_btn.pack(side=tk.LEFT, padx=10)
    
    root.mainloop()

def open_web_ui(icon, item):
    """打开Web界面"""
    webbrowser.open("http://127.0.0.1:16880")
    logger.info("已打开Web UI")

def toggle_autostart(icon, item):
    """切换开机自启"""
    current = is_autostart_enabled()
    set_autostart(not current)

def toggle_idm_auto_download(icon, item):
    """切换idm自动下载"""
    current = is_idm_auto_download()
    set_idm_auto_download(not current)

def regenerate_secret_key(icon, item):
    """重新生成密钥"""
    result = show_custom_message(
        "确认", 
        "重新生成密钥将使旧客户端失效，是否继续？", 
        "question"
    )
    
    if result:
        new_key = secrets.token_urlsafe(32)
        config["secret_key"] = new_key
        save_config(config)
        logger.info("安全密钥已重新生成")
        show_custom_message("成功", "新密钥已生成并保存！", "success")

def quit_app(icon, item):
    """退出应用"""
    result = show_custom_message("确认", "确定要退出 IDM Agent 吗？", "question")
    if result:
        logger.info("程序正在退出...")
        icon.stop()
        os._exit(0)

# --- 主程序 ---
def run_flask():
    """运行Flask服务"""
    # 本地测试环境
    app.run(host='127.0.0.1', port=16880, debug=False, threaded=True)

def main():
    """主函数"""
    # 启动Flask线程
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logger.info("IDM Agent 已启动，监听端口 16880")
    
    # 创建托盘图标
    image = create_image()
    
    # 创建托盘菜单
    menu = (
        pystray.MenuItem("打开 Web UI", open_web_ui),
        pystray.MenuItem(
            "开机自动启动",
            toggle_autostart,
            checked=lambda item: is_autostart_enabled()
        ),
        pystray.MenuItem(
            "IDM自动下载",
            toggle_idm_auto_download,
            checked=lambda item: is_idm_auto_download()
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("显示当前密钥", show_secret_key),
        pystray.MenuItem("重新生成密钥", regenerate_secret_key),
        pystray.MenuItem("设置 IDM 路径", set_idm_path),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("退出", quit_app)
    )
    
    # 启动托盘
    icon = pystray.Icon("IDM-Agent", image, "IDM 下载代理", menu)
    icon.run()

# --- 入口点 ---
if __name__ == '__main__':
    # 设置tkinter高清显示
    try:
        tk.CallWrapper().func = lambda *args: None  # 修复高DPI问题
        if hasattr(tk, 'tk') and tk.tk.call('tk', 'scaling') < 1.0:
            tk.tk.call('tk', 'scaling', 1.2)
    except:
        pass
    
    main()

# 打包
# pyinstaller --onefile --windowed --name IDM-Agent main.py
