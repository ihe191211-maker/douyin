#!/usr/bin/env bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
UID_DY=$(adb shell dumpsys package com.ss.android.ugc.aweme 2>/dev/null | grep -m1 -oE 'userId=[0-9]+' | grep -oE '[0-9]+')
adb shell "su -c 'iptables  -D OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT'" 2>/dev/null || true
adb shell "su -c 'ip6tables -D OUTPUT -p udp --dport 443 -m owner --uid-owner $UID_DY -j REJECT'" 2>/dev/null || true
echo "[*] 已移除 UDP443 封锁,恢复正常上网(QUIC)。"
