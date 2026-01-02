from flask import Flask, send_from_directory
import os

app = Flask(__name__, static_folder='ruanjcg', template_folder='ruanjcg')

# 配置中文显示
app.config['JSON_AS_ASCII'] = False

# 定义路由，访问根目录时返回闪屏页
@app.route('/')
def index():
    return send_from_directory(app.static_folder, '闪屏.html')

# 通用路由，用于访问所有HTML文件
@app.route('/<path:filename>')
def serve_html(filename):
    if filename.endswith('.html'):
        return send_from_directory(app.static_folder, filename)
    # 对于其他文件，使用Flask的静态文件处理
    return send_from_directory(app.static_folder, filename)

# 处理可能的404错误
@app.errorhandler(404)
def page_not_found(e):
    return f"页面未找到: {e}", 404

if __name__ == '__main__':
    # 启动服务器，允许外部访问，端口5000
    app.run(host='0.0.0.0', port=5000, debug=True)