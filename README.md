# nDPI Entropy GUI

**nDPI Entropy GUI** 是一个基于 [nDPI](https://github.com/ntop/nDPI) 的图形化分析工具，用于检测和识别可疑的加密流量（例如 Shadowsocks隧道）。  
本工具提供直观的 GUI 界面，帮助研究人员和安全运营人员快速筛选高熵流量，并结合端口聚类与地理定位，辅助发现潜在的翻墙隧道或可疑服务器。

---

## ✨ 功能特性

- **图形化界面 (Tkinter)**：无需命令行，轻松加载 PCAP 文件并启动分析  
- **Shadowsocks 流量检测**：利用熵值特征识别自首字节即为密文的流量  
- **可疑服务器聚类**：基于 `(server_ip, port)` 聚合，识别潜在代理服务端  
- **地理定位支持**：  
  - 在线：调用 `ip-api.com` 作为兜底  
- **结果导出**：一键导出高熵流量 CSV 报表
- **使用**：ndpi编译后将/example/ndpiReader二进制文件放在与nDPI_Entropy_GUI.py放在同目录下运行即可

