# -*- coding: utf-8 -*-
import os
import sys
import json
import time
import hashlib
import hmac
import secrets
import re
import logging
import subprocess
from datetime import datetime, timedelta
from urllib.parse import unquote
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import winreg
from PIL import Image, ImageDraw
from flask import Flask, request, jsonify, render_template_string
import pystray
from pystray import MenuItem as item
from logging.handlers import TimedRotatingFileHandler

# 获取程序所在目录
if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(os.path.abspath(__file__))

# 配置文件路径
CONFIG_FILE = os.path.join(app_dir, "config.json")
BLACKLIST_FILE = os.path.join(app_dir, "blacklist.json")

# 默认配置
DEFAULT_CONFIG = {
    "secret_key": "",
    "idm_path": r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe",
    "listen_local_only": True,
    "auto_start": False,
    "idm_auto_download": False,
    "max_failures": 5,
    "ban_duration": 3600,
    "time_window": 60
}

# 日志配置
def setup_logger():
    log_dir = Path(app_dir) / "logs"
    log_dir.mkdir(exist_ok=True)
    
    logger = logging.getLogger("IDMAgent")
    logger.setLevel(logging.INFO)
    
    # 按天轮转的文件处理器
    file_handler = TimedRotatingFileHandler(
        log_dir / "agent.log",
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8"
    )
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    
    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    )
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

class ConfigManager:
    def __init__(self):
        self.config = DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    self.config.update(saved_config)
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
    
    def save_config(self):
        """保存配置文件"""
        try:
            # 保存完整配置包括密钥
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
    
    def get_secret_key(self):
        """获取密钥"""
        return self.config.get('secret_key', '')

config_manager = ConfigManager()

def generate_secret_key():
    """生成随机密钥"""
    return secrets.token_hex(32)

def generate_md5_signature(params, secret):
    items = [(k, v) for k, v in params.items() if k != 'sign' and v is not None]
    items.sort(key=lambda x: x[0])
    raw = '&'.join(f"{k}={v}" for k, v in items) + secret
    return hashlib.md5(raw.encode('utf-8')).hexdigest()

def verify_md5_signature(params, signature):
    """验证MD5签名"""
    secret_key = config_manager.get_secret_key()
    if not secret_key:
        logger.warning("未设置密钥，无法验证签名")
        return False
    
    # 验证时间戳
    time_window = config_manager.config['time_window'] * 1000
    try:
        ts = int(params.get('ts', 0))
    except (ValueError, TypeError):
        logger.warning("ts 无效")
        return False
    
    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts) > time_window:
        logger.warning("签名已过期")
        return False
    
    expected_sig = generate_md5_signature(params, secret_key)
    return hmac.compare_digest(expected_sig, signature)

def is_url(url):
    """简单验证URL格式"""

    pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url is not None and pattern.search(url) is not None

def sanitize_filename(filename):
    """清理文件名"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename.strip()

def load_blacklist():
    """加载黑名单"""
    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"加载黑名单失败: {e}")
    return {}

def save_blacklist(blacklist):
    """保存黑名单"""
    try:
        with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(blacklist, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"保存黑名单失败: {e}")

def is_ip_blacklisted(ip):
    """检查IP是否在黑名单中"""
    blacklist = load_blacklist()
    if ip in blacklist:
        ban_info = blacklist[ip]
        ban_time = datetime.fromisoformat(ban_info['timestamp'])
        duration = timedelta(seconds=ban_info['duration'])
        if datetime.now() - ban_time < duration:
            return True
        else:
            # 清除过期的封禁
            del blacklist[ip]
            save_blacklist(blacklist)
    return False

def add_to_blacklist(ip, reason=""):
    """添加IP到黑名单"""
    blacklist = load_blacklist()
    blacklist[ip] = {
        'timestamp': datetime.now().isoformat(),
        'duration': config_manager.config['ban_duration'],
        'reason': reason
    }
    save_blacklist(blacklist)
    logger.info(f"IP {ip} 已加入黑名单，原因: {reason}")

# 全局变量用于控制Flask应用
flask_app_instance = None
flask_thread = None
shutdown_event = threading.Event()

def run_flask_app():
    """运行Flask应用"""
    global flask_app_instance
    failure_counts = {}
    
    app = Flask(__name__)
    flask_app_instance = app  # 保存实例以便重启时使用
    
    @app.after_request
    def after_request(response):
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        return response

    @app.route('/download', methods=['OPTIONS'])
    def handle_options():
        return '', 200
    
    @app.route('/download', methods=['GET', 'POST'])
    def add_download():
        """核心下载接口（完全重构，无阻塞）"""
        client_ip = request.remote_addr
        
        try:
            # 检查IP是否在黑名单中
            if is_ip_blacklisted(client_ip):
                logger.warning(f"黑名单IP {client_ip} 尝试访问")
                return jsonify({"code": 400, "message": "Forbidden - IP blocked"}), 200
            
            # 2. 解析参数（容错处理）
            params = {
                "url": "",
                "filename": "",
                "ts": ""
            }
            signature = ""
            
            try:
                if request.method == 'POST':
                    if request.is_json:
                        data = request.get_json(silent=True) or {}
                    else:
                        data = request.form.to_dict()
                    params["url"] = data.get('url', '').strip()
                    params["filename"] = data.get('filename', '').strip()
                    params["ts"] = data.get('ts', '').strip()
                    signature = data.get('sign', '').strip()
                else:
                    params["url"] = request.args.get('url', '').strip()
                    params["filename"] = request.args.get('filename', '').strip()
                    params["ts"] = request.args.get('ts', '').strip()
                    signature = request.args.get('sign', '').strip()
            except Exception as e:
                logger.error(f"解析参数失败: {e}")
                # 记录失败次数
                failure_counts[client_ip] = failure_counts.get(client_ip, 0) + 1
                if failure_counts[client_ip] >= config_manager.config['max_failures']:
                    add_to_blacklist(client_ip, "参数解析失败")
                    del failure_counts[client_ip]  # 清除计数
                return jsonify({"code": 400, "message": "Parameter parsing failed"}), 200
            
            # 3. 检查必填参数（极简版）
            if not all([params['url'], params['ts'], signature]):
                logger.warning(f"客户端 {client_ip} 缺少必要参数: url={bool(params['url'])}, ts={bool(params['ts'])}, sign={bool(signature)}")
                # 记录失败次数
                failure_counts[client_ip] = failure_counts.get(client_ip, 0) + 1
                if failure_counts[client_ip] >= config_manager.config['max_failures']:
                    add_to_blacklist(client_ip, "缺少必要参数")
                    del failure_counts[client_ip]  # 清除计数
                return jsonify({"code": 400, "message": "Missing required fields: url, ts, sign"}), 200
            
            # 4. 验证签名
            if not verify_md5_signature(params, signature):
                logger.warning(f"客户端 {client_ip} 签名验证失败")
                # 记录失败次数
                failure_counts[client_ip] = failure_counts.get(client_ip, 0) + 1
                if failure_counts[client_ip] >= config_manager.config['max_failures']:
                    add_to_blacklist(client_ip, "签名验证失败")
                    del failure_counts[client_ip]  # 清除计数
                return jsonify({"code": 400, "message": "Invalid or expired signature"}), 200
            
            # 5. 检查URL有效性
            if not is_url(params['url']):
                logger.warning(f"客户端 {client_ip} 无效URL: {params['url']}")
                # 记录失败次数
                failure_counts[client_ip] = failure_counts.get(client_ip, 0) + 1
                if failure_counts[client_ip] >= config_manager.config['max_failures']:
                    add_to_blacklist(client_ip, "无效URL")
                    del failure_counts[client_ip]  # 清除计数
                return jsonify({"code": 400, "message": "Invalid URL"}), 200
            
            # 如果验证通过，清除失败计数
            if client_ip in failure_counts:
                del failure_counts[client_ip]
            
            # 6. 执行IDM下载
            try:
                idm_exe = config_manager.config["idm_path"]
                if not os.path.isfile(idm_exe):
                    logger.error(f"IDM 未找到: {idm_exe}")
                    return jsonify({"code": 400, "message": f"IDM not found: {idm_exe}"}), 200
                
                url = unquote(params['url'])
                logger.info(f"合法请求来自 {client_ip}: {url}")
                
                # 构建命令
                cmd = [idm_exe, "/d", url]
                if params['filename']:
                    filename = unquote(params['filename'])
                    filename = sanitize_filename(filename)
                    if filename:
                        cmd.extend(["/f", filename])
                
                if config_manager.config["idm_auto_download"]:
                    cmd.append("/n")
                
                # 执行命令（无阻塞）
                subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                return jsonify({"code": 0, "message": "Download sent to IDM"}), 200
            
            except Exception as e:
                logger.error(f"执行下载失败: {e}", exc_info=True)
                return jsonify({"code": 400, "message": f"Download failed: {str(e)}"}), 200
        except Exception as e:
            logger.error(f"捕获异常: {e}", exc_info=True)
            return jsonify({"code": 400, "message": "Internal server error"}), 200

    @app.route('/')
    def index():
        """WebUI首页"""
        client_ip = request.remote_addr
        if is_ip_blacklisted(client_ip):
            return "Forbidden - IP blocked", 200
            
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
    
    host = '127.0.0.1' if config_manager.config['listen_local_only'] else '0.0.0.0'
    app.run(host=host, port=16880, debug=False, threaded=True, use_reloader=False)

def restart_flask_app():
    """重启Flask应用以应用新配置"""
    threading.Thread(target=_restart_flask_app, daemon=True).start()

def _restart_flask_app():
    global flask_thread, shutdown_event
    
    # 设置关闭事件，让当前线程结束
    if shutdown_event:
        shutdown_event.set()
    
    # 等待当前线程结束
    if flask_thread and flask_thread.is_alive():
        flask_thread.join(timeout=5)  # 最多等待5秒
    
    # 重置关闭事件
    shutdown_event.clear()
    
    # 启动新的Flask应用线程
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    logger.info("Web服务已重启")

# 全局变量：用于保存主窗口实例
_main_window = None
_window_created = False  # 新增：标记窗口是否已创建

def create_tray_icon():
    """创建系统托盘图标"""
    def create_image():
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
    
    def show_main_window():
        """显示主窗口（修复焦点问题）"""
        global _main_window, _window_created

        def force_focus(window):
            """强制获取焦点的辅助函数"""
            window.deiconify()
            window.lift()
            window.focus_force()
            window.attributes('-topmost', True)
            window.update()
            window.attributes('-topmost', False)
            # 给第一个可聚焦的控件设置焦点
            for widget in window.winfo_children():
                if widget.winfo_children():
                    for child in widget.winfo_children():
                        try:
                            child.focus_set()
                            return
                        except:
                            continue
                try:
                    widget.focus_set()
                    return
                except:
                    continue

        if not _window_created:
            # 首次创建窗口
            root = tk.Tk()
            root.title("IDM Agent 配置")
            root.geometry("700x400")
            root.resizable(True, True)

            # 居中
            root.update_idletasks()
            x = (root.winfo_screenwidth() // 2) - (700 // 2)
            y = (root.winfo_screenheight() // 2) - (400 // 2)
            root.geometry(f"700x400+{x}+{y}")

            # 关闭窗口时隐藏而非销毁
            def on_closing():
                root.withdraw()  # 隐藏窗口
            root.protocol("WM_DELETE_WINDOW", on_closing)

            # 构建 UI（和原来一样）
            notebook = ttk.Notebook(root)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # === 基本设置页 ===
            basic_frame = ttk.Frame(notebook)
            notebook.add(basic_frame, text="基本设置")

            # IDM路径设置
            idm_path_var = tk.StringVar(value=config_manager.config['idm_path'])
            ttk.Label(basic_frame, text="IDM路径:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            idm_path_entry = ttk.Entry(basic_frame, textvariable=idm_path_var, width=50)
            idm_path_entry.grid(row=0, column=1, padx=5, pady=5)
            
            # 保存IDM路径的回调函数
            def save_idm_path(*args):
                path = idm_path_var.get()
                if path:
                    if os.path.isfile(path) and os.path.basename(path).lower() == "idman.exe":
                        config_manager.config['idm_path'] = path
                        config_manager.save_config()
                    else:
                        # 恢复原有值
                        idm_path_var.set(config_manager.config['idm_path'])
                        if not os.path.isfile(path):
                            messagebox.showerror("错误", f"IDM程序不存在: {path}", parent=root)
                        else:
                            messagebox.showwarning("警告", f"IDM程序文件名应为 IDMan.exe，当前为: {os.path.basename(path)}", parent=root)
            
            idm_path_var.trace_add('write', save_idm_path)
            
            def browse_idm_path(var):
                """浏览IDM路径"""
                # 创建一个隐藏的根窗口用于文件对话框，确保对话框有父窗口
                temp_root = tk.Tk()
                temp_root.withdraw()  # 隐藏这个临时窗口
                temp_root.call('wm', 'attributes', '.', '-topmost', True)
                
                path = filedialog.askopenfilename(
                    parent=temp_root,
                    title="选择IDM程序",
                    filetypes=[("EXE files", "*.exe"), ("All files", "*.*")]
                )
                
                # 销毁临时窗口
                temp_root.destroy()
                
                if path:
                    var.set(path)
            
            ttk.Button(basic_frame, text="浏览", command=lambda: browse_idm_path(idm_path_var)).grid(row=0, column=2, padx=5, pady=5)

            # 监听模式设置
            ttk.Label(basic_frame, text="监听模式:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
            local_only_var = tk.BooleanVar(value=config_manager.config['listen_local_only'])
            
            def save_listen_mode(*args):
                old_value = config_manager.config['listen_local_only']
                new_value = local_only_var.get()
                if old_value != new_value:
                    config_manager.config['listen_local_only'] = new_value
                    config_manager.save_config()
                    # 询问是否重启服务
                    if messagebox.askyesno("重启服务", "监听模式更改需要重启Web服务才能生效，是否立即重启？", parent=root):
                        restart_flask_app()
            
            local_only_var.trace_add('write', save_listen_mode)
            ttk.Checkbutton(basic_frame, text="仅本地访问", variable=local_only_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

            # IDM自动下载设置，默认覆盖文件
            ttk.Label(basic_frame, text="自动下载:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            auto_download_var = tk.BooleanVar(value=config_manager.config['idm_auto_download'])
            
            def save_auto_download(*args):
                config_manager.config['idm_auto_download'] = auto_download_var.get()
                config_manager.save_config()
            
            auto_download_var.trace_add('write', save_auto_download)
            ttk.Checkbutton(basic_frame, text="启用", variable=auto_download_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

            # 开机自启设置
            ttk.Label(basic_frame, text="开机自启:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
            auto_start_var = tk.BooleanVar(value=config_manager.config['auto_start'])
            
            def toggle_auto_start(*args):
                """切换开机自启"""
                key = winreg.HKEY_CURRENT_USER
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                try:
                    registry_key = winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE)
                    new_value = auto_start_var.get()
                    
                    if new_value:
                        # 添加自启项
                        exe_path = os.path.abspath(sys.argv[0])
                        winreg.SetValueEx(registry_key, "IDMAgent", 0, winreg.REG_SZ, exe_path)
                    else:
                        # 删除自启项
                        winreg.DeleteValue(registry_key, "IDMAgent")
                    
                    winreg.CloseKey(registry_key)
                    
                    config_manager.config['auto_start'] = new_value
                    config_manager.save_config()
                except Exception as e:
                    logger.error(f"设置开机自启失败: {e}")
                    # 恢复原有值
                    auto_start_var.set(config_manager.config['auto_start'])
                    messagebox.showerror("错误", f"设置开机自启失败: {e}", parent=root)
            
            auto_start_var.trace_add('write', toggle_auto_start)
            ttk.Checkbutton(basic_frame, text="启用", variable=auto_start_var).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)

            # === 安全设置页 ===
            security_frame = ttk.Frame(notebook)
            notebook.add(security_frame, text="安全设置")

            secret_actual_var = tk.StringVar()
            secret_display_var = tk.StringVar()

            ttk.Label(security_frame, text="密钥:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            secret_container = ttk.Frame(security_frame)
            secret_container.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)

            secret_masked_entry = ttk.Entry(secret_container, textvariable=secret_display_var, width=32, state="readonly")
            secret_masked_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

            button_container = ttk.Frame(secret_container)
            button_container.pack(side=tk.RIGHT, padx=(5, 0))

            def toggle_secret_visibility():
                actual = secret_actual_var.get()
                if visibility_btn.cget("text") == "显示":
                    secret_display_var.set(actual)
                    visibility_btn.config(text="隐藏")
                else:
                    secret_display_var.set("*" * len(actual))
                    visibility_btn.config(text="显示")

            def copy_secret():
                actual = secret_actual_var.get()
                if actual:
                    root.clipboard_clear()
                    root.clipboard_append(actual)
                    messagebox.showinfo("提示", "密钥已复制到剪贴板", parent=root)
                else:
                    messagebox.showwarning("警告", "没有密钥可复制", parent=root)

            def generate_new_secret():
                old_secret = secret_actual_var.get()
                new_secret = generate_secret_key()
                secret_actual_var.set(new_secret)
                
                # 保存新密钥
                config_manager.config['secret_key'] = new_secret
                config_manager.save_config()

                # 询问是否重启服务
                if messagebox.askyesno("重启服务", "密钥更改需要重启Web服务才能生效，是否立即重启？", parent=root):
                    restart_flask_app()
                
            visibility_btn = ttk.Button(button_container, text="显示", command=toggle_secret_visibility)
            copy_btn = ttk.Button(button_container, text="复制", command=copy_secret)
            generate_btn = ttk.Button(button_container, text="生成", command=generate_new_secret)
            visibility_btn.pack(side=tk.LEFT, padx=2)
            copy_btn.pack(side=tk.LEFT, padx=2)
            generate_btn.pack(side=tk.LEFT, padx=2)

            secret_actual_var.set(config_manager.get_secret_key())
            secret_display_var.set("*" * len(secret_actual_var.get()))
            secret_actual_var.trace_add("write", lambda *a: (
                secret_display_var.set(secret_actual_var.get() if visibility_btn.cget("text") == "隐藏" else "*" * len(secret_actual_var.get()))
            ))

            # 最大失败次数设置
            max_failures_var = tk.IntVar(value=config_manager.config['max_failures'])
            ttk.Label(security_frame, text="最大失败次数:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
            
            def save_max_failures(*args):
                config_manager.config['max_failures'] = max_failures_var.get()
                config_manager.save_config()
            
            max_failures_var.trace_add('write', save_max_failures)
            ttk.Spinbox(security_frame, from_=1, to=100, textvariable=max_failures_var).grid(row=2, column=1, padx=5, pady=5)

            # 封禁时长设置
            ban_duration_var = tk.IntVar(value=config_manager.config['ban_duration'])
            ttk.Label(security_frame, text="封禁时长(秒):").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
            
            def save_ban_duration(*args):
                config_manager.config['ban_duration'] = ban_duration_var.get()
                config_manager.save_config()
            
            ban_duration_var.trace_add('write', save_ban_duration)
            ttk.Spinbox(security_frame, from_=60, to=86400, textvariable=ban_duration_var).grid(row=3, column=1, padx=5, pady=5)

            # 时间窗口设置
            time_window_var = tk.IntVar(value=config_manager.config['time_window'])
            ttk.Label(security_frame, text="时间窗口(秒):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
            
            def save_time_window(*args):
                config_manager.config['time_window'] = time_window_var.get()
                config_manager.save_config()
            
            time_window_var.trace_add('write', save_time_window)
            ttk.Spinbox(security_frame, from_=10, to=300, textvariable=time_window_var).grid(row=4, column=1, padx=5, pady=5)

            # === 黑名单管理页 ===
            blacklist_frame = ttk.Frame(notebook)
            notebook.add(blacklist_frame, text="黑名单管理")

            main_container = ttk.Frame(blacklist_frame)
            main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            text_frame = ttk.Frame(main_container)
            text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            blacklist_text = tk.Text(text_frame, height=15, state=tk.DISABLED)
            scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=blacklist_text.yview)
            blacklist_text.configure(yscrollcommand=scrollbar.set)
            blacklist_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            button_frame = ttk.Frame(main_container, width=100)
            button_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(5, 0))
            button_frame.pack_propagate(False)

            def refresh_blacklist():
                blacklist_text.config(state=tk.NORMAL)
                blacklist_text.delete(1.0, tk.END)
                blacklist = load_blacklist()
                for ip, info in blacklist.items():
                    line = f"{ip} | {info['reason']} | {info['timestamp']}\n"
                    blacklist_text.insert(tk.END, line)
                blacklist_text.config(state=tk.DISABLED)

            def add_to_blacklist_manual():
                ip = simpledialog.askstring("添加IP", "请输入要封禁的IP地址:", parent=root)
                if ip:
                    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                        messagebox.showerror("错误", "IP地址格式不正确", parent=root)
                        return
                    add_to_blacklist(ip, "手动添加")
                    refresh_blacklist()

            def delete_from_blacklist():
                try:
                    selected = blacklist_text.get(tk.SEL_FIRST, tk.SEL_LAST)
                    ip = selected.split(' | ')[0].strip()
                    blacklist = load_blacklist()
                    if ip in blacklist:
                        del blacklist[ip]
                        save_blacklist(blacklist)
                        refresh_blacklist()
                        messagebox.showinfo("成功", f"IP {ip} 已移除", parent=root)
                    else:
                        messagebox.showwarning("警告", "未找到选中的IP", parent=root)
                except tk.TclError:
                    messagebox.showwarning("警告", "请先选中要删除的IP条目", parent=root)

            def clear_blacklist():
                if messagebox.askyesno("确认", "确定要清空所有黑名单吗？", parent=root):
                    save_blacklist({})
                    refresh_blacklist()

            ttk.Button(button_frame, text="刷新", command=refresh_blacklist).pack(fill=tk.X, pady=2)
            ttk.Button(button_frame, text="添加IP", command=add_to_blacklist_manual).pack(fill=tk.X, pady=2)
            ttk.Button(button_frame, text="删除选中", command=delete_from_blacklist).pack(fill=tk.X, pady=2)
            ttk.Button(button_frame, text="清空", command=clear_blacklist).pack(fill=tk.X, pady=2)

            refresh_blacklist()

            _main_window = root  # 保存全局引用
            _window_created = True  # 标记窗口已创建
            
            # 首次显示时强制获取焦点
            force_focus(root)
            
            # 启动主循环
            root.mainloop()

        else:
            # 已存在窗口：强制恢复显示并获取焦点
            try:
                # 检查窗口是否还存在（防止异常关闭）
                _main_window.winfo_exists()
                
                # 强制恢复显示和焦点
                force_focus(_main_window)
                
            except:
                # 窗口已被销毁，重新创建
                _window_created = False
                show_main_window()
    
    def quit_app(icon, item):
        """退出应用"""
        # 设置关闭事件
        shutdown_event.set()
        # 关闭托盘图标
        icon.stop()
        # 退出程序
        os._exit(0)
    
    # 创建托盘图标
    image = create_image()
    menu = (
        item('打开配置', show_main_window),
        item('退出', quit_app),
    )
    
    icon = pystray.Icon("IDM Agent", image, "IDM Agent", menu)
    return icon


def main():
    """主函数"""
    logger.info("IDM Agent 启动中...")
    
    # 检查是否已生成密钥
    if not config_manager.get_secret_key():
        secret = generate_secret_key()
        config_manager.config['secret_key'] = secret
        config_manager.save_config()
        logger.info("已生成新密钥，请在配置界面查看")
    
    # 启动Flask应用
    global flask_thread
    flask_thread = threading.Thread(target=run_flask_app, daemon=True)
    flask_thread.start()
    
    # 创建并启动托盘图标
    icon = create_tray_icon()
    icon.run()

if __name__ == "__main__":
    main()

# 打包
# pyinstaller --onefile --windowed --name IDM-Agent main.py
