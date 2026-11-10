### 灵宠空间中转站部署指南（Cloudflare Worker） 
1. 创建 Worker
- 注册 Cloudflare 账号（免费即可）
- 进入 Workers & Pages → Overview → Create → Create Worker
- 给 Worker 起个名字（比如`spirit-pet` ），点 Deploy
- 复制 worker.js 全文粘贴到 Worker 的编辑器里，点 Save and Deploy
2. 绑定 KV 存储（必需）
- Worker 部署成功后，进入 Settings → Variables and Secrets → KV Namespace Bindings
- 点 Add ，Variable name 填`BOX` （ 必须叫这个名，代码里硬编码的 ）
- 点右侧 Create a namespace ，起个名字（比如`pet-box` ），Save
- 回到 Worker 页面，重新 Save and Deploy
3. 配置 CORS 白名单（可选）

如果只想让指定网页调用，在 Settings → Variables and Secrets → Environment Variables 里添加：

- Variable name:`ALLOW_ORIGINS`
- Value: 允许的网页域名，多个用逗号分隔（例如`https://mypet.pages.dev` ）
- 留空 = 不限
4. 获取 Worker 地址
- Worker 页面顶部显示`https://<你的名字>.<子域>.workers.dev`
- 把这个地址配置到前端 HTML （灵宠空间.html）的「中转白名单」里即可


免费额度参考
指标 每天 请求数 10 万 KV 读 10 万 KV 写/删 各 1000 存储总量 1 GB

小圈子（< 10 人）完全够用。
