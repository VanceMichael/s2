# 让虚拟主机式 S3 请求保持同一资源身份

> **Workspace:** /Users/vance/project/mineProject/swe/09101006/project-01

---

**User**

使用把桶名放在域名前缀中的 AWS SDK 连接本地对象存储时，请求不能被解释成另一个 path-style 资源，也不能因为内部改写路径而失去原有签名。请为 S3 监听器提供可选的服务域名配置，使形如 photos.s3.local.test:9000/dir/a%20b.txt 的请求在全部现有桶、对象、复制和 multipart 操作中稳定指向 bucket=photos 与原始 key；Authorization header 和 presigned URL 都必须继续按客户端实际签署的 Host、path 与 query 验证，改动其中任一项仍会拒绝，认证后的 principal policy 也要针对同一个逻辑资源判定。服务域名本身的根路径继续承担 ListBuckets 和健康检查，而桶域名下与健康路径同名的 key 必须作为对象处理；只有精确匹配已配置后缀且前缀是合法单段桶名的 Host 才采用虚拟主机寻址，端口、尾点、非法桶标签和未知 Host 要有确定结果，不能静默落到另一只桶。未配置该能力时所有请求保持现有 path-style 行为，配置后 path-style、Web Console、CORS、错误 XML 与现有 SDK 回归也不得改变。

**Assistant**

我先了解一下代码库结构，确认这是哪个 S3 实现以及现有的路由、签名、策略校验代码。

toolName: Shell

status: success

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/server.go

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/s3api.go

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/utils.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/middleware/sigv4.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/policy.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/buckets.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/objects.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/multipart.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/buckets.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/user.go

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/s3api_test.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/middleware/sigv4_test.go

我已经理解了整体架构。让我再确认 Go 版本（是否支持 `r.SetPathValue`）以及 handler 测试中如何签名。

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/go.mod

toolName: search_by_regex

status: success

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/s3/integ_test.go

Go 1.26，`SetPathValue` 可用。再确认所有 S3 路由注册点和 config 测试风格。

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config_test.go

架构已明确。这是 `s2-server`：path-style ServeMux 路由，SigV4 在每个 handler 上包裹。我的方案是：**新增独立的 vhost mux，完全不改写 wire path**——签名照旧用请求的 Host/path/query 验证，bucket 仅通过 `SetPathValue` 注入给 handler。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/vhost.go

changes: undefined

toolName: todo_write

status: success

Todos updated: 7 items

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config.go

changes: undefined

toolName: todo_write

status: success

Todos updated: 7 items

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/s3api.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/buckets.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/objects.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/multipart.go

changes: undefined

先编译验证一下，确认 ServeMux 模式不冲突。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: Shell

status: success

编译通过。现在写分类器单元测试。

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/vhost_test.go

changes: undefined

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config_test.go

在 config_test.go 末尾追加 S3Domain 的规范化与环境变量测试。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/config_test.go

changes: undefined

toolName: Shell

status: success

单元测试通过。现在写 vhost 端到端测试，先确认 models 里的 XML 类型名称。

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/models.go

现在确认从 server 包外部如何构造 Policy（`stringOrSlice` 未导出）。

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/buckets_test.go

现在编写完整的端到端测试文件。

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

清理 TestVHostDeleteObjects 里残留的草稿代码。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

toolName: search_by_regex

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

toolName: todo_write

status: success

Todos updated: 7 items

toolName: Shell

status: success

ServeMux 的 `/{key...}` 通配符匹配零段（即 `/`），与 `/{$}` 根模式在 GET/HEAD 自动匹配上冲突。path-style 现有代码本身就是靠**空 key 委托**处理这种情况（handleGetObject/PutObject 等在 key=="" 时委托给桶 handler）。vhost 注册表去掉全部 `/{$}` 模式，只保留五个 `/{key...}`，根操作走同一套既有委托逻辑。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/buckets.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/objects.go

changes: undefined

toolName: Shell

status: success

toolName: Shell

status: success

时间戳偏差 8 小时——签名时用了本地 `time.Now()`（UTC+8）却标 `Z`。全部改为 `time.Now().UTC()`。

toolName: Shell

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go

changes: undefined

toolName: Shell

status: success

19 个 vhost 端到端测试全部通过。现在跑全量测试确认无回归。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-01/go.work

toolName: Shell

status: success

toolName: Shell

status: success

`go test ./...` 在 workspace 下只覆盖根模块。逐模块跑。

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

全部通过。最后审查一遍整体改动。

toolName: Shell

status: success

`go build` 在 cmd 目录留下了二进制文件，删掉。

toolName: delete_file

status: success

全部完成。更新任务状态。

toolName: todo_write

status: success

Todos updated: 7 items

## 实现总结

核心原则：**全程不改写 wire URL**。虚拟主机请求用独立 mux 路由，bucket 仅在 ServeMux 匹配后通过 `r.SetPathValue` 注入，签名验证看到的始终是客户端实际签署的 Host/path/query。

### 改动文件

- [vhost.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/vhost.go)（新增）：Host 分类器 `matchBucketHost`、vhost 注册表与 mux 构建、`virtualHostRouter` 分发
- [config.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/config.go)：新增 `S3Domain`（JSON `s3_domain`，环境变量 `S2_SERVER_S3_DOMAIN`）与 `normalizeS3Domain` 规范化校验
- [s3api.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/s3api.go#L59-L65)：将分类器接入中间件链
- [objects.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/objects.go#L762-L769) / [multipart.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/multipart.go#L550-L553)：注册 vhost 路由（GET/HEAD/PUT/DELETE/POST `/{key...}`）
- 测试：[vhost_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/vhost_test.go)、[vhost_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/handlers/s3api/vhost_test.go)、[config_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-01/server/config_test.go#L471-L527)

### 关键行为

| Host | 结果 |
|---|---|
| `photos.s3.local.test:9000/dir/a%20b.txt` | bucket=photos，key=`dir/a b.txt`（原始 key，含空格） |
| `s3.local.test`（裸域） | `/` = ListBuckets，`/healthz` = 健康检查，path-style 照旧 |
| `photos.s3.local.test/healthz` | 作为**对象**处理（vhost 分支无 health 中间件） |
| 尾点（`...test.`）、非法标签（大写/过短/多点前缀/下划线） | 确定的 **400 InvalidArgument** XML，不会落到 path-style 被解释成别的桶 |
| 未知 Host（IP、localhost、`evils3.local.test`） | path-style，桶只来自路径首段，行为不变 |
| 未配置 `S3Domain` | 路由器直接透传原链路，零行为变化 |

签名安全：Authorization header 与 presigned URL 均按 wire 的 Host、canonical path、raw query 验证——测试覆盖篡改 Host/路径/query 任一项均 403，presigned 过期/篡改同样拒绝；policy 用同一逻辑资源（Host bucket + 原始 key）判定，含空格 key 的精确 ARN 也已覆盖。

multipart 完整生命周期（initiate/uploadPart/complete/abort）和 CopyObject 在桶域名下全程签名通过。所有现有模块测试与 `go vet` 干净，Web Console、CORS、错误 XML 路径无改动。
