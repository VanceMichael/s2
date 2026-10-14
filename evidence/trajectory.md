# 让浏览器签名 POST 表单只发布合规对象

> **Workspace:** /Users/vance/project/mineProject/swe/09101006/project-02

---

**User**

前端拿到 presigned POST 表单后直接向本地桶提交文件时，S3 端点应像现有预签名 PUT 一样完成认证和落盘，而不必把文件先转发给应用服务器。请在 bucket 级 POST 入口接收 AWS SigV4 multipart/form-data 表单，使用表单中的 credential、algorithm、date、base64 policy 和 signature 解析现有用户身份并校验签名与过期时间，再以最终展开的 bucket/key 对 principal 的 s3:PutObject 权限做真实资源检查。Policy 中针对 bucket、key、Content-Type、自定义 x-amz-meta 字段的精确和 starts-with 条件以及 content-length-range 都必须约束实际提交值，${filename} 只能由上传文件名替换，缺失、重复、未被 policy 约束或互相矛盾的安全字段不得被忽略。文件大小按文件本身而非整个 multipart 请求计算，并继续受服务端上传上限约束；只有全部验证和后端写入成功后对象、metadata 与 Content-Type 才可见，签名错误、条件不符、断流、超限、临时文件或存储失败都不能破坏同名旧对象，并应清理中间资源后允许修正重试。默认成功、success_action_status=201 与合法 success_action_redirect 分别返回 S3 兼容状态、PostResponse 或重定向，Location、bucket、key 和 ETag 必须描述实际写入；原有 DeleteObjects、header/query SigV4、presigned PUT、multipart upload 和 Web Console 上传保持不变。

**Assistant**

我先探索代码库，了解项目结构和现有的预签名 PUT 等实现。

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/s3api.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/objects.go

Now let me read the policy engine, user context, config, and utils.

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/policy.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/user.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/utils.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/models.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/server.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/storage.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/config.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/object.go

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/fs/atomic.go

Now let me examine metadata storage, the s3 backend's Upload requirements, and existing test helpers.

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/metadata.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/fs/object.go

toolName: search_by_regex

status: success

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/s3api_test.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/integration_test.go

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/contenttype.go

toolName: search_by_regex

status: success

Let me check name validation and the buckets manager.

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

I now understand the architecture. Let me set up a task list and check a few remaining details.

toolName: todo_write

status: success

Todos updated: 6 items

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/go.mod

Now implementing. First, the POST signature verifier in the middleware package.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4.go

changes: undefined

Let me clean up that awkward unused-variable handling.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4.go

changes: undefined

Now the main handler file.

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

I need to fix several issues in that draft: retain the multipart reader for the trailing-part check, thread the filename properly, and remove a hacky import. Rewriting the file.

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

Now add the `PostResponse` model.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/models.go

changes: undefined

Now wire the routes — update objects.go registration.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/objects.go

changes: undefined

Now update multipart.go: the object-level POST entry and trailing-slash delegation.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go

changes: undefined

toolName: search_by_regex

status: success

Now let's build to catch compile errors.

toolName: Shell

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

toolName: Shell

status: success

Build is clean. Now writing comprehensive tests.

toolName: todo_write

status: success

Todos updated: 6 items

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

The test file has a few rough edges to fix. Let me correct them.

toolName: edit_file_search_replace

status: failed

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: search_by_regex

status: success

toolName: Shell

status: success

Now fix the GET helper (escape key segments), remove the dead `cases` block and the placeholder helper, and fix imports.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: Shell

status: success

toolName: search_by_regex

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: Shell

status: success

toolName: Shell

status: success

Several test-expectation issues. Let me see the metadata failure detail first.

toolName: Shell

status: success

toolName: Shell

status: success

The metadata write reports success but GET sees none. Let me debug what's actually stored.

toolName: Shell

status: success

toolName: Shell

status: success

Metadata is stored. Let me check the HTTP GET path.

toolName: Shell

status: success

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/zz_debug_test.go

changes: undefined

toolName: Shell

status: success

toolName: Shell

status: success

Found it — plain GET is 403 in auth mode (no signature). The test helper needs SigV4-signed GET. Let me fix the helper and the other three test issues, and remove the debug file.

toolName: delete_file

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: Shell

status: success

Two test-side fixes: the GET signer must re-encode the canonical URI, and the no-Content-Type check should inspect the stored object rather than platform MIME behavior.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: Shell

status: success

The test client auto-follows the 303. Disable redirects on the test server's client.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go

changes: undefined

toolName: Shell

status: success

All new tests pass. Now add middleware-level unit tests for `VerifyPostPolicyV4`.

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4_test.go

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

Now the full server test suite for regressions.

toolName: todo_write

status: success

Todos updated: 6 items

toolName: Shell

status: success

All server tests pass. Now the workspace root and lint.

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

toolName: Shell

status: success

Let me remove the unused `conds` field from `evaluatedPolicy` (kept only written, never read).

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/.golangci.yml

toolName: search_by_regex

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

toolName: Shell

status: success

golangci-lint exists in GOPATH/bin. Running it.

toolName: Shell

status: success

Lint is clean. Let me check whether existing docs enumerate supported S3 APIs, so the feature list stays consistent.

toolName: search_by_regex

status: success

No docs updates needed. Let me do a final full build across the workspace and re-run the complete server test suite once more.

toolName: Shell

status: success

Let me avoid per-request middleware closure allocations by hoisting the wrapped handlers to package-level variables.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go

changes: undefined

The empty-key branch in `handleObjectPOST` is now dead (the entry intercepts it). Remove it.

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go

changes: undefined

toolName: Shell

status: success

Let me verify real-world interop with boto3's `generate_presigned_post` if Python/boto3 is available.

toolName: Shell

status: success

Let me do a final review of the complete implementation.

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go

Implementation looks complete. Final verification with the race detector on the affected packages.

toolName: Shell

status: success

toolName: Shell

status: success

toolName: todo_write

status: success

Todos updated: 6 items

已完成 bucket 级 presigned POST 直传支持，浏览器拿到表单后可直接向 S3 端点提交，文件不再经过应用服务器。全部构建、vet、golangci-lint、全量测试与 `-race` 均通过，既有能力无回归。

## 实现要点

**签名与身份**（[sigv4.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4.go#L233-L289)）
- 新增 `VerifyPostPolicyV4`：校验 `x-amz-algorithm`、解析五段 `x-amz-credential` 并查出现有 User、校验 `x-amz-date` 与凭证日期一致，再用同一套 SigV4 派生密钥对**提交原样的 base64 policy** 做常量时间 HMAC 比对；不做 15 分钟时钟偏移（有效期完全由 policy `expiration` 决定）。

**POST 入口与条件校验**（[postobject.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject.go)）
- 流式解析 multipart：文本字段逐个限量读取（单字段 64 KiB、字段数 256），重复字段、缺失 key/file、文件后还有字段、保留元数据键 `s2-etag` 全部拒绝；签名错误/策略过期返回 403，格式错误返回 400。
- 顺序：base64/JSON 解析 → 验签 → 过期检查 → 条件求值 → IAM 鉴权 → 桶存在性 → 落盘。
- policy 支持对象简写与数组形式的 `eq`/`starts-with`/`content-length-range`，针对 bucket、展开后的 key、Content-Type、`x-amz-meta-*` 精确/前缀匹配；区间取交集，矛盾区间直接拒绝；任何未被 policy 约束的非豁免字段一律 403；`${filename}` 仅由上传文件名替换，其他 `${...}` 保持字面量。
- 以最终展开的 bucket/key 调 `server.AllowedS3Action(s3:PutObject)` 做真实资源检查。

**大小与原子性**
- 文件先入临时文件并**只按文件字节计数**（policy 上限与服务端 `MaxUploadSize` 双重生效），断流→`IncompleteBody`，超限→`EntityTooLarge`/`EntityTooSmall`；校验全部通过后才调 `s2.Upload`（osfs 临时文件+rename 原子提交），任何失败都不触碰同名旧对象，临时文件 defer 清理，可立即修正重试（测试逐项验证旧 body/Content-Type/metadata 不变且无残留临时文件）。

**响应**：默认 204；`success_action_status` 支持 200/204/201（201 返回 [PostResponse](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/models.go#L66-L75)，Location 支持 `X-Forwarded-Proto`）；合法 `success_action_redirect` 返回 303 并带 `${filename}` 替换及 bucket/key/etag 查询参数。Location、bucket、key、ETag 均取自实际写入结果。

**路由兼容**：[objects.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/objects.go#L754-L761) 与 [multipart.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/multipart.go#L529-L565) 新增 entry 分发——仅当无 `Authorization`/presigned 查询、非 `?delete` 且 Content-Type 为 multipart/form-data 时才走 POST 验签；DeleteObjects、header/query SigV4、presigned PUT、分片上传、Web Console 上传路径完全不变。

**测试**：[postobject_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/handlers/s3api/postobject_test.go) 覆盖 40+ 场景（各类成功响应、签名/凭证/过期、全部条件类型、限额、畸形表单、失败原子性与临时文件清理、IAM 前缀授权、无认证模式、`?delete` 回归），另在 [sigv4_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-02/server/middleware/sigv4_test.go) 为验签函数补了单元测试。
