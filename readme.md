
---

# RSA GUI Tool

一个简洁美观、纯本地运行的 RSA 加解密图形化工具。支持生成不同规格的 RSA 密钥对，并提供消息加解密功能。中英双语界面，开源可本地运行，无需依赖在线服务。

---

## ✨ 功能 Features

1.  **RSA 密钥对生成**
    *   支持 512 / 1024 / 2048 / 4096 bit 四种规格
    *   默认生成 1024 bit 密钥对
2.  **RSA 公钥加密**
    *   输入公钥和明文信息
    *   输出加密后的密文报文 (Base64 编码)
3.  **RSA 私钥解密**
    *   输入私钥和密文报文 (Base64 编码)
    *   输出解密后的明文信息
4.  **增强功能**
    *   界面启动时自动居中。
    *   一键清除所有输入输出内容。
    *   生成密钥后自动填充私钥到解密页面。
    *   复制操作无弹窗提示，体验更流畅。
    *   公钥/私钥复制按钮位置优化。

---

## 📦 环境 Environment

*   **Python 版本**: 3.8 ~ 3.11 (推荐 3.9+)
*   **依赖库**:
    *   `tkinter` (通常随 Python 一起安装，用于图形界面)
    *   `pycryptodome` (用于 RSA 加解密)
    *   `PyInstaller` (用于打包成可执行文件，可选)

安装依赖：

```bash
pip install pycryptodome
```

> **注意**: `tkinter` 通常包含在标准 Python 安装中。如果运行时提示缺少 `tkinter`，请根据您的操作系统和 Python 安装方式额外安装。例如，在某些 Linux 发行版上，您可能需要运行 `sudo apt-get install python3-tk`。

---

## ▶️ 运行 Run

1.  确保已安装所需依赖 (`pycryptodome`)。
2.  将 `rsa.txt` 文件重命名为 `rsa.py` (如果尚未重命名)。
3.  在命令行中导航到 `rsa.py` 文件所在的目录。
4.  执行以下命令启动程序：

```bash
python rsa.py
```

---

## 🔨 构建可执行文件 Build Executable

您可以使用 [PyInstaller](https://pyinstaller.org/) 将 Python 脚本打包成独立的可执行文件 (如 Windows 上的 `.exe` 文件)，方便在没有 Python 环境的机器上分发和运行。

### 1. 安装 PyInstaller

```bash
pip install pyinstaller
```

### 2. 执行构建命令

在包含 `rsa.py` 文件的目录下，打开命令行并运行以下命令来构建一个**单文件**的可执行程序：

```bash
pyinstaller --onefile --windowed rsa.py
```

**命令参数说明:**

*   `pyinstaller`: 调用 PyInstaller 工具。
*   `--onefile`: 指示 PyInstaller 将所有内容（包括 Python 解释器、代码、库、资源等）打包成一个单独的可执行文件。这使得分发更简单，但启动速度可能略慢于多文件模式。
*   `--windowed`: (在 Windows 上也常写成 `-w`) 指示 PyInstaller 不要为 GUI 应用程序打开控制台窗口。这对于没有命令行交互的桌面应用是必需的，可以避免出现黑色的命令行窗口。
*   `rsa.py`: 这是您要打包的主 Python 脚本文件名。

### 3. 查找生成的文件

构建过程完成后（可能需要几分钟），您将在项目目录下看到以下新文件和文件夹：

*   `build/`: 包含构建过程中生成的中间文件。
*   `dist/`: 包含最终生成的可执行文件。
*   `rsa.spec`: PyInstaller 的配置文件，可用于更高级的构建配置。

生成的可执行文件（例如，在 Windows 上是 `rsa.exe`）将位于 `dist/` 目录下。您可以直接运行这个文件。

### 4. (可选) 使用 UPX 压缩可执行文件

为了减小生成的可执行文件的体积，您可以使用 [UPX](https://upx.github.io/) 进行压缩。

1.  下载并安装 UPX。
2.  将 UPX 的可执行文件路径添加到系统环境变量 `PATH` 中，或者在命令行中直接指定其完整路径。
3.  在命令行中运行以下命令（将 `dist/rsa.exe` 替换为您实际生成的可执行文件路径）：

    ```bash
    upx dist/rsa.exe
    ```

---

## 📖 说明 Notes

*   本工具完全在本地运行，处理的数据不会发送到任何外部服务器，保证了数据安全和隐私。
*   界面支持中英文切换，适合不同用户群体。
*   适合学习 RSA 加密原理、测试加解密流程和日常轻量级的加解密使用。
*   代码结构清晰，易于理解和修改。

---
