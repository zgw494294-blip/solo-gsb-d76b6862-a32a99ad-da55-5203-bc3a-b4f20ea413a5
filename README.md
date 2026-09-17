# JSON 数据脱敏工作台

本地运行的 JSON 数据脱敏工具：粘贴 JSON → 编排脱敏规则 → 并排预览 → 导出脱敏结果与审计清单。

- 后端：FastAPI + SQLite + jsonpath-ng
- 前端：原生 HTML / CSS / JavaScript（无构建步骤）
- 交付：Docker 一键启动

## 快速启动

```bash
docker compose up --build
```

启动后访问：**http://localhost:8000**（API 文档：http://localhost:8000/docs）

> 也可以不用 compose，直接构建镜像：
> ```bash
> docker build -t json-masking-workbench .
> docker run -p 8000:8000 -e MASK_SALT=your-secret-salt json-masking-workbench
> ```

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MASK_SALT` | `please-change-me`（compose）/ `local-dev-salt`（裸镜像） | 带盐哈希的**默认盐**。规则可单独覆盖；**生产使用务必修改** |
| `PORT` | `8000` | 容器内服务端口；compose 下同时作为宿主机映射端口（`PORT=9000 docker compose up` → 访问 :9000） |
| `DATA_DIR` | `/data`（容器）/ `./data`（本地） | SQLite 存储目录，**只保存规则模板** |

配置方法（任选其一）：

```bash
# 1. 命令行注入
MASK_SALT=my-secret docker compose up --build

# 2. .env 文件（compose 自动读取）
echo 'MASK_SALT=my-secret' > .env
docker compose up --build
```

## 功能说明

### 四种脱敏动作

| 动作 | 说明 | 参数 |
|---|---|---|
| 删除 | 从结果中移除该节点 | — |
| 掩码 | 替换为掩码字符 | 掩码字符、保持原长度 / 固定长度 |
| 带盐哈希 | `sha256(盐 + 规范JSON值)` 截断 | 盐（留空用 `MASK_SALT`）、输出长度 |
| 稳定编号 | 同值同号、异值异号，如 `USER-0001` | 编号前缀 |

### 规则匹配语义

- 规则按**优先级数值从小到大**依次执行，同优先级按列表顺序；
- **同一路径只执行第一条命中的规则**，后续规则对该路径（及其子孙）不再生效；
- **父节点被删除后，其所有子路径不再处理**（报告中标记为“已跳过”）；
- 每条规则作用于上一条规则处理后的结果树（列表元素被删除后下标会前移）；
- 稳定编号在**每条规则内**按值首次出现的文档顺序分配；同一输入重复运行结果完全一致。

### 预览与报告

- 预览并排显示原始 JSON 与脱敏结果；
- 路径命中报告列出文档中**每一条路径**：命中（规则名/动作）、未命中、已跳过（父节点被删）；
- 支持按状态筛选，原值/结果值并列展示。

### 模板与导出

- 规则可保存为模板（SQLite 持久化，容器卷 `masking-templates`），支持加载 / 更新 / 另存 / 删除；
- 导出物：**脱敏 JSON**（`masked.json`）、**审计清单**（`audit.json` / `audit.csv`）。

## 数据安全设计

- 原始 JSON 只在内存中处理，**绝不写入 SQLite、日志或任何文件**；
- SQLite 仅保存规则模板（路径、动作、参数），不含用户数据；
- 审计清单不含原值：仅 hash / number 条目保留脱敏产物（哈希值 / 编号），未命中、被删除、被掩码的路径一律不带值；
- 含原值的命中报告仅存在于预览响应中，即用即弃。

## API 一览

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/health` | 健康检查 |
| `POST` | `/api/preview` | 脱敏预览，返回 `{masked, report, audit}` |
| `GET` | `/api/templates` | 模板列表 |
| `POST` | `/api/templates` | 新建模板 |
| `GET` / `PUT` / `DELETE` | `/api/templates/{id}` | 模板查询 / 更新 / 删除 |

`POST /api/preview` 请求体示例：

```json
{
  "data": {"users": [{"name": "张三", "phone": "13800001111"}]},
  "rules": [
    {"name": "姓名编号", "path": "$.users[*].name", "action": "number", "priority": 10, "prefix": "USER"},
    {"name": "手机哈希", "path": "$.users[*].phone", "action": "hash", "priority": 20, "hash_length": 16}
  ]
}
```

JSONPath 语法由 [jsonpath-ng](https://pypi.org/project/jsonpath-ng/) 扩展解析器支持，如 `$.a.b`、`$..email`、`$.users[*].phone`、`$.items[0]`。

## 本地开发（不用 Docker）

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

运行引擎测试：

```bash
python3 tests/test_engine.py    # 或 pytest tests/
```

## 项目结构

```
├── Dockerfile            # 一体化镜像（依赖安装 + 初始化 + 启动）
├── compose.yaml          # 一键启动编排
├── requirements.txt
├── app/
│   ├── main.py           # FastAPI 入口与 API
│   ├── masking.py        # 脱敏引擎（优先级/消费/稳定编号）
│   ├── db.py             # SQLite 模板存储（仅存模板）
│   ├── schemas.py        # 请求/响应模型
│   └── static/           # 原生前端（index.html / app.js / style.css）
└── tests/test_engine.py  # 引擎语义测试
```
