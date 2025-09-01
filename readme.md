
# RSA GUI Tool

一个简洁美观、纯本地运行的 RSA 加解密图形化工具。支持生成不同规格的 RSA 密钥对，并提供消息加解密功能。中英双语界面，开源可本地运行，无需依赖在线服务。

---

## ✨ 功能 Features

1. **RSA 密钥对生成**  
   - 支持 512 / 1024 / 2048 / 4096 bit 四种规格  
   - 默认生成 1024 bit 密钥对  

2. **RSA 公钥加密**  
   - 输入公钥和明文信息  
   - 输出加密后的密文报文  

3. **RSA 私钥解密**  
   - 输入私钥和密文报文  
   - 输出解密后的明文信息  

---

## 📦 环境 Environment

- **Python 版本**: 3.8 ~ 3.11  
- **依赖库**:
  - `PyQt5` (图形界面)  
  - `pycryptodome` (RSA 加解密)  

安装依赖：
```bash
pip install pyqt5 pycryptodome
````

---

## ▶️ 运行 Run

```bash
python rsa.py
```

---

## 🔨 构建可执行文件 Build Executable

使用 [PyInstaller](https://pyinstaller.org/) 打包为独立 `.exe`：

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole rsa.py
```

生成的可执行文件在 `dist/` 目录下。

为减小体积，建议使用 [UPX](https://upx.github.io/) 进一步压缩：

```bash
upx dist/rsa.exe
```

---

## 📖 说明 Notes

* 本工具仅限本地使用，不会产生额外的配置文件或目录。
* 界面支持中英文切换，适合不同用户群体。
* 适合学习、测试和日常加解密使用。