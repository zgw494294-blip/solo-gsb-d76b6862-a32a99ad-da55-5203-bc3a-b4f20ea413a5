# 本地 JSON 数据脱敏工作台

FastAPI + SQLite + jsonpath-ng 后端，原生 HTML/CSS/JavaScript 前端（无构建、无 CDN，内网离线可用）。
粘贴 JSON 后，用 JSONPath 编排 **删除 / 掩码 / 带盐哈希 / 稳定编号** 四类规则，并排预览原值与结果，
保存规则模板，并导出脱敏 JSON 与审计清单。

## 一条命令启动

```bash
docker compose up --build -d
```

启动后访问：**http://localhost:8000**

停止：`docker compose down`（加 `-v` 可同时删除存放模板的命名卷 `masking_data`）。

> 需要 Docker Engine 20.10+ 且启用 Compose v2（`docker compose`）。不支持 v1 时可改用
> `docker-compose up --build -d`（compose.yaml 格式与 v1/v2 均兼容）。

## 环境变量

| 变量 | 必需 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `MASKING_HASH_SALT` | 使用 hash 规则时**必需** | `please-change-this-dev-salt`（仅开发兜底，见下） | 带盐哈希的全局盐，参与 SHA-256：`sha256(全局盐 \\x00 规则盐 \\x00 规范JSON值)`。建议 `openssl rand -hex 32` 生成。**盐值变更会导致同一输入哈希结果变化。** |
| `PORT` | 否 | `8000` | 宿主机映射端口（容器内固定监听 8000）。 |
| `MAX_BODY_BYTES` | 否 | `10485760`（10 MiB） | 单次请求体大小上限，超限返回 413。 |
| `SQLITE_PATH` | 否 | `/data/masking.db` | 模板库文件路径，已挂载命名卷持久化。 |

配置方法（任选其一）：

1. 复制 `.env.example` 为 `.env` 后修改，`docker compose` 会自动读取；
2. 或在命令行临时注入：

```bash
MASKING_HASH_SALT="$(openssl rand -hex 32)" PORT=8080 docker compose up --build -d
```

未设置 `MASKING_HASH_SALT` 时：删除/掩码/编号规则可正常使用；执行命中 hash 规则的预览或导出会返回
`400` 并提示缺少盐，避免无盐哈希误用。

## 规则语义

规则字段：`name`（名称）、`path`（JSONPath，jsonpath-ng 扩展语法，支持 `$..a`、`[*]`、
`[?(@.x>1)]` 等）、`action`、`priority`（数字越小越先）、`enabled`、`params`。

| 动作 | 参数 | 说明 |
| --- | --- | --- |
| `delete` 删除 | — | 移除键或数组元素；父节点被删除后，其所有子路径不再处理。 |
| `mask` 掩码 | `keep_first`、`keep_last`、`mask_char`、`mask_length`（空=与隐藏位等长） | 保留首尾字符，其余替换为掩码字符；非字符串值先转规范 JSON 文本。 |
| `hash` 带盐哈希 | `salt`（规则盐）、`length`（1–64，SHA-256 十六进制截断长度） | 同值同哈希、异值异哈希，结果可逆抗性依赖盐保密。 |
| `number` 稳定编号 | `prefix`、`suffix`、`padding`（补零宽度，0 不补）、`start` | **每条规则独立计数**，按深度优先首次出现顺序分配；同值同号、异值异号。 |

匹配与执行规则（核心需求）：

1. **按优先级匹配**：规则按 `priority` 升序（相同优先级按编排顺序），逐条对 JSONPath 求值。
2. **同一路径只执行首条**：一个具体路径若被多条规则命中，只有优先级最高者执行，其余记为
   `skipped`（未执行）并在界面与审计清单标明原因。
3. **父节点处理后子路径不再处理**：祖先路径已被某规则命中（无论删除还是整体替换为标量），
   后代路径上的规则记为 `blocked`（阻断），不再执行、也不消耗稳定编号。
4. **稳定可复现**：编号只依赖值首次出现的 DFS 顺序，哈希只依赖盐与规范 JSON；同一输入、同一规则、
   同一盐值重复运行，结果逐字节一致。规则以 `enabled:false` 关闭时不参与匹配。

## 界面与 API

打开 http://localhost:8000：

- 左侧粘贴/格式化 JSON、编排规则（可上移调整、设置每条规则参数）、保存与加载模板；
- 右侧**并排树**显示原值与结果，节点徽标标明命中规则与动作，未命中叶子标“未命中”；
- 明细表逐路径列出：命中规则（优先级、动作）、未执行/阻断的规则及原因、对该路径未命中的规则；
  可勾选“仅看命中路径”；
- “导出脱敏 JSON”下载 `masked.json`；“导出审计清单”下载 `audit.json`。

API（请求体均为 `{"document": <JSON对象或数组>, "rules": [...]}`）：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/mask/preview` | 预览：结果 + 每路径命中/未命中明细 + 汇总 |
| POST | `/api/mask/export` | 仅返回脱敏后的 JSON（`Content-Disposition: attachment`） |
| POST | `/api/mask/audit` | 审计清单（仅路径、规则、状态，无任何值） |
| GET/POST | `/api/templates` | 列出 / 新建规则模板 |
| PUT/DELETE | `/api/templates/{id}` | 更新 / 删除模板 |
| GET | `/api/health` | 健康检查与盐配置状态 |

快速调用示例：

```bash
curl -sS http://localhost:8000/api/mask/preview \
  -H 'Content-Type: application/json' \
  -d '{"document":{"phone":"13812345678"},"rules":[{"name":"手机","path":"$..phone","action":"mask","priority":1,"params":{"keep_first":3,"keep_last":2}}]}'
```

## 安全边界（原值不落库、不进日志、不进审计）

- **SQLite 只存规则模板**（表 `templates`：名称、说明、规则 JSON、时间戳）。原始数据、原值、
  脱敏结果从不写库；`/data` 卷里也不会出现业务数据。
- **应用日志只记录启动与模板库路径**；请求体、规则匹配过程、原值均不写日志（uvicorn 默认访问日志
  只含方法与路径，不含请求体）。
- **审计清单**（`/api/mask/audit` 与界面导出）只含路径、规则名/动作/优先级、命中/未执行/阻断/
  未命中状态及原因、规则级计数，**不含原值、结果值，也不含任何盐**。
- 脱敏 JSON 是唯一包含变换后值的导出物；hash 输出不可逆但可被同盐比对，请勿将其当作加密。
- 本工具定位为**本地单机工作台**，默认无鉴权、仅绑定你映射的本机端口；不要直接暴露到公网。
  如需多人使用请置于内网 SSO/网关之后。

## 目录结构

```
.
├── Dockerfile              # python:3.12-slim + 依赖 + 健康检查
├── compose.yaml            # 一键编排（端口/环境变量/命名卷/healthcheck）
├── scripts/entrypoint.sh   # 容器启动：建目录、盐告警、启动 uvicorn
├── requirements.txt
├── app/
│   ├── main.py             # FastAPI 路由
│   ├── engine.py           # 匹配/优先级/阻断/掩码/哈希/编号引擎（纯函数）
│   ├── db.py               # SQLite 模板存储
│   ├── schemas.py          # 请求模型
│   ├── config.py           # 环境变量配置
│   └── static/             # index.html / styles.css / app.js（原生前端）
└── tests/                  # 引擎与 API 语义测试（不打入镜像）
```

## 本地开发（不用 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
MASKING_HASH_SALT=dev-salt uvicorn app.main:app --reload --port 8000
# 测试
PYTHONPATH=. python tests/test_engine.py
PYTHONPATH=. python tests/test_api.py
```
