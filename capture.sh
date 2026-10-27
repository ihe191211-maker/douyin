#!/usr/bin/env bash
# 用法: ./capture.sh [秒数] [过滤词...]
# 例:  ./capture.sh 120 normal
set -e
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
PKG=com.ss.android.ugc.aweme
UID_DY=$(adb shell dumpsys package $PKG 2>/dev/null | grep -m1 -oE 'userId=[0-9]+' | grep -oE '[0-9]+')
SECS=${1:-120}; shift || true
echo "[*] 抖音 uid=$UID_DY"
echo "[*] 启动 frida-server..."
adb shell "su -c 'pidof frida-server'" >/dev/null 2>&1 || \
  adb shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
sleep 1
echo "[*] 封 UDP443(逼 API 回落 TCP)..."
adb shell "su -c 'iptables -C OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT 2>/dev/null || iptables -I OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT'" 2>/dev/null || true
adb shell "su -c 'ip6tables -C OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT 2>/dev/null || ip6tables -I OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT'" 2>/dev/null || true
echo "[*] 请确认手机上抖音已在信息流页面!  ${SECS}s 抓取开始..."
python h2parse.py "$SECS" attach "$@"
