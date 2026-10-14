# 让认证配置轮换在请求边界原子生效

> **Workspace:** /Users/vance/project/mineProject/swe/09101006/project-03

---

**User**

运维者轮换配置文件中的 S3 或 Web Console 凭证和用户策略时，应能向正在服务的进程发送 SIGHUP 完成重载，而不必为一次认证变更中断对象请求。每次重载都要按启动时相同的 default、配置文件、环境变量和显式命令行参数优先级构造候选配置并完成整体验证，但运行期间只允许 legacy user/password、users 及其 policy 发生变化；监听地址、存储类型与根目录、初始桶、健康路径、上传限制和其他运行资源字段一旦漂移，就拒绝发布整份候选并继续使用旧配置。SigV4 的 Authorization header、query presign、匿名 principal 与 Console BasicAuth 必须在单个请求开始时取得同一份完整认证快照，已进入认证流程的请求继续使用原 generation，发布成功后的新请求统一使用新 generation，不能把旧 secret、新 principal 或不同版本的 policy 混在一次判定中。配置文件缺失、JSON 或 policy 无效、access key 重复以及不可变字段改变时，服务仍以旧 generation 正常响应，并留下可区分成功和失败的日志；修复来源后再次发送 SIGHUP 可以恢复。没有配置文件、认证未启用和未发送 SIGHUP 的部署保持原行为，连续 SIGHUP 与 SIGINT 或 SIGTERM 交错时也必须有界收敛，不能泄漏重载协程、发布半份配置或阻塞现有优雅关闭。

**Assistant**

我先了解项目结构和现有实现，再规划方案。

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/go.mod

toolName: Shell

status: success

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/config.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/cmd/s2-server/main.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/server.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/user.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/sigv4.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/basicauth.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/s3api.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/console.go

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/config.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/server_test.go

toolName: Shell

status: success

toolName: search_by_regex

status: success

Let me look at the test harness and remaining pieces before designing.

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/templates.go

toolName: search_by_regex

status: success

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/policy.go

Now I have the full picture. Let me check a few remaining details: handler module layout, middleware test conventions, and the docs passage that explicitly says no SIGHUP exists.

toolName: Shell

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/docs/users-policy.md

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/sigv4_test.go

toolName: search_by_regex

status: success

方案已明确。开始实现。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload.go

changes: undefined

toolName: todo_write

status: success

Todos updated: 7 items

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/server.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/server.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/server.go

changes: undefined

Now update the two middleware entry points to snapshot once per request.

toolName: todo_write

status: success

Todos updated: 7 items

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/sigv4.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/basicauth.go

changes: undefined

先编译检查。

toolName: Shell

status: success

编译通过。现在写单元测试。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload_test.go

changes: undefined

检查是否已有外部测试包及可能的路由注册冲突。

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/s3api_test.go

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/policy.go

toolName: Write

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

修正签名器中 SHA256 计算的错误用法。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

运行新增测试。

toolName: Shell

status: success

单元测试全通过。运行端到端信号测试。

toolName: Shell

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

遇到 Go `os/signal` 的已知竞态：Run 内部 `signal.Stop` 与刚送达的 SIGTERM 过于贴近时，信号可能落回默认处置杀掉测试进程。测试侧用一个先行注册、最后注销的信号持有通道消除该窗口。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

重复运行时全局路由重复注册导致 panic，用 `sync.Once` 保护。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

通过了，但单次耗时偏长（约 12s）。用 -v 看时间分布。

toolName: Shell

status: success

功能全部正确，但关闭耗时 10s。怀疑是测试客户端 keep-alive 空闲连接导致。换成禁用 keep-alive 的客户端验证。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

定位 10s 是哪个环节——先测已有的带 HTTP 请求的 Start 测试耗时。

toolName: Shell

status: success

直接在测试中分段计时定位。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

Run 在 SIGTERM 后 102µs 即返回——10s 在测试体其他位置。加分段计时排查。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

找到原因：清理兜底逻辑中对已读取的 `errCh` 二次接收永远阻塞，白等 10 秒还多发了一次 SIGTERM。改用 `runDone` 关闭通道判断。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

移除临时计时代码。

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go

changes: undefined

toolName: Shell

status: success

约 2s/次。现在跑全量 server 包（含 -race）和中间件测试。

toolName: todo_write

status: success

Todos updated: 7 items

toolName: edit_file_search_replace

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/docs/users-policy.md

changes: undefined

toolName: search_by_regex

status: success

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/Makefile

按项目测试约定运行全量测试，server 模块加 -race。

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

全部测试与 vet 通过。最后通读一遍核心生产代码确认。

toolName: view_files

status: success

filePath: /Users/vance/project/mineProject/swe/09101006/project-03/server/reload.go

所有验证通过。完成收尾。

toolName: todo_write

status: success

Todos updated: 7 items

SIGHUP 热重载已实现，所有测试（含 `-race`）通过。

## 实现要点

**世代化配置存储**（[reload.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/reload.go)）
- `configStore` 用 `atomic.Pointer` 持有 `{*Config, generation}`，发布即单次原子指针交换，世代号 CAS 单调递增；旧世代 Config 永不修改，被在途请求的局部指针引用时由 GC 保留。
- `buildConfig` 抽取启动时的 default → 配置文件 → 环境变量 → 显式 flag 优先级，重载按完全相同的顺序构造候选。
- `ReloadConfig`：候选先过整份 `Config.Validate`，再过 `checkImmutableFields`——仅允许 legacy `user`/`password`、`users` 及其 policy 变化；监听地址、`console_listen`、`health_path`、上传/预览/分片限制、初始桶、嵌入的存储 `type/root/signed_url/S3/GCS/Azblob` 任一漂移即整份拒绝。

**信号循环**（[server.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/server.go#L116-L226)）
- 无配置文件时不注册 SIGHUP（`newReloadSignals` 返回 nil），部署行为与原来一致。
- SIGHUP 通道缓冲为 1：突发信号在运行时侧最多挂起一个，多余信号由运行时丢弃，而每次重载都重新读盘，有限突发有界收敛到最新文件；每个信号不产生协程。
- SIGINT/SIGTERM 驱动的优雅关闭与重载无锁交集：关闭不等待重载；关闭竞态期间最多完成一次已开始的重载。
- 日志可区分：成功 `Configuration reloaded generation=N`，失败 `Configuration reload failed; continuing with previous configuration generation=K error=...`（区分缺文件/JSON/policy/重复 key/不可变漂移）。

**请求级认证快照**（[sigv4.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/sigv4.go#L40-L57)、[basicauth.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/middleware/basicauth.go#L26-L38)）
- 每个请求入口取一次 `srv.CurrentConfig()`，Authorization header、query presign、匿名 principal 三个分支共用同一 `lookup`；匹配到的 `*User` 及后续 `Authorized`、`WithUser` 全部来自同一世代，杜绝旧 secret 配新 principal/跨版本 policy。新请求一律用新世代。

## 测试

- [reload_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/reload_test.go)：并发发布世代单调、旧世代指针隔离、优先级、全部不可变字段（13 项）拒绝、坏 JSON/缺文件/重复 key/坏 policy/不可变漂移均保持世代 2，修复后恰为世代 3。
- [run_reload_test.go](file:///Users/vance/project/mineProject/swe/09101006/project-03/server/run_reload_test.go)：真实 `Run` + HTTP，覆盖 SigV4 header/presign、匿名主体、Console BasicAuth 的轮换前后行为、坏文件继续服务、修复恢复、监听漂移拒绝且老端口仍服务、50 连发 SIGHUP 收敛、关认证重载、20 SIGHUP 与 SIGTERM 交错下毫秒级优雅退出。
- [users-policy.md](file:///Users/vance/project/mineProject/swe/09101006/project-03/docs/users-policy.md#L46) 中原"必须重启、无 SIGHUP 处理"段落已更新为重载语义说明。

验证：`go test -short ./...` 全模块通过；server 模块 `go test -short -race ./...` 全部通过；`gofmt`/`go vet` 干净。
