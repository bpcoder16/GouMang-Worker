# 安全白名单配置说明

## 概述

GouMang-Worker 实现了基于白名单的命令执行安全策略，只允许执行指定目录下的特定类型文件，有效防止恶意命令执行。

## 配置文件

安全配置文件位于：`/conf/security.yaml`

## 配置项说明

### 基础配置

```yaml
security:
  enableValidation: true  # 是否启用安全验证
```

### 路径白名单配置

```yaml
allowedPaths:
  - path: "/opt/scripts"    # 允许的目录路径
    description: "脚本目录" # 描述信息
    recursive: true         # 是否允许子目录
    maxDepth: 5            # 最大子目录深度（-1 表示无限制）
```

**参数说明：**
- `path`: 绝对路径，只有此路径下的文件才能被执行
- `recursive`: 是否允许访问子目录
- `maxDepth`: 子目录最大深度限制
  - `0`: 只允许当前目录
  - `>0`: 允许指定深度的子目录
  - `-1`: 无深度限制

### 解释器白名单配置

```yaml
allowedInterpreters:
  - name: "python"                           # 解释器名称
    executables: ["python", "python3"]      # 允许的可执行文件名
    fileExtensions: [".py"]                  # 允许的文件扩展名
    description: "Python 脚本执行器"         # 描述信息
```

**支持的解释器类型：**

1. **Python 脚本**
   ```yaml
   - name: "python"
     executables: ["python", "python3", "python3.8", "python3.9"]
     fileExtensions: [".py", ".pyw"]
   ```

2. **PHP 脚本**
   ```yaml
   - name: "php"
     executables: ["php", "php8", "php7"]
     fileExtensions: [".php"]
   ```

3. **Shell 脚本**
   ```yaml
   - name: "shell"
     executables: ["bash", "sh", "zsh"]
     fileExtensions: [".sh", ".bash", ".zsh"]
   ```

4. **Node.js 脚本**
   ```yaml
   - name: "node"
     executables: ["node", "nodejs"]
     fileExtensions: [".js", ".mjs"]
   ```

5. **二进制可执行文件**
   ```yaml
   - name: "binary"
     executables: []        # 空数组表示直接执行
     fileExtensions: [""]   # 无扩展名
   ```

### 命令解析安全配置

```yaml
commandParsing:
  allowPipes: false        # 是否允许管道操作 (|)
  allowRedirection: false  # 是否允许重定向 (>, >>, <)
  allowBackground: false   # 是否允许后台执行 (&)
  allowChaining: false     # 是否允许命令链接 (&&, ||, ;)
```

### 日志配置

```yaml
logging:
  logDeniedCommands: true   # 记录被拒绝的命令
  logAllowedCommands: false # 记录允许的命令
```

## 使用示例

### 1. 执行 Python 脚本

**配置：**
```yaml
allowedPaths:
  - path: "/opt/scripts"
    recursive: true
    maxDepth: 3
allowedInterpreters:
  - name: "python"
    executables: ["python3"]
    fileExtensions: [".py"]
```

**允许的命令：**
```bash
python3 /opt/scripts/test.py
python3 /opt/scripts/data/process.py
python3 /opt/scripts/tools/backup/daily.py
```

**被拒绝的命令：**
```bash
python3 /tmp/malicious.py          # 路径不在白名单
python /opt/scripts/test.py        # 解释器不在白名单
python3 /opt/scripts/test.txt      # 文件扩展名不匹配
```

### 2. 执行二进制文件

**配置：**
```yaml
allowedPaths:
  - path: "/usr/local/bin/custom"
    recursive: false
    maxDepth: 0
allowedInterpreters:
  - name: "binary"
    executables: []
    fileExtensions: [""]
```

**允许的命令：**
```bash
/usr/local/bin/custom/backup-tool
/usr/local/bin/custom/data-processor
```

### 3. 安全限制示例

**被拒绝的危险命令：**
```bash
rm -rf /                           # 危险模式检测
python3 /opt/scripts/test.py | grep # 管道操作被禁用
python3 /opt/scripts/test.py > log   # 重定向被禁用
python3 /opt/scripts/test.py &       # 后台执行被禁用
python3 /opt/scripts/test.py && ls   # 命令链接被禁用
$(cat /etc/passwd)                   # 命令替换被禁用
```

## 最佳实践

### 1. 目录结构建议

```
/opt/scripts/
├── python/          # Python 脚本
│   ├── data/
│   └── tools/
├── shell/           # Shell 脚本
│   ├── backup/
│   └── maintenance/
└── php/             # PHP 脚本
    └── web/
```

### 2. 安全配置建议

- **生产环境**: 启用所有安全限制
- **开发环境**: 可适当放宽限制，但保持路径白名单
- **测试环境**: 建议与生产环境保持一致

### 3. 监控和审计

- 启用 `logDeniedCommands` 监控攻击尝试
- 定期检查日志中的异常命令
- 根据实际需求调整白名单配置

## 故障排除

### 1. 命令被拒绝

检查日志中的具体拒绝原因：
- 路径是否在白名单中
- 解释器是否被允许
- 文件扩展名是否匹配
- 是否包含危险模式

### 2. 验证器初始化失败

检查配置文件：
- 文件路径是否正确
- YAML 语法是否正确
- 权限是否足够

### 3. 性能考虑

- 路径验证会进行文件系统访问
- 建议合理设置 `maxDepth` 避免深度遍历
- 考虑缓存验证结果（未来版本实现）

## 配置模板

参考 `conf_default/security.yaml` 获取完整的配置模板。