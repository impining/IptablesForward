#!/usr/bin/env bash
#===============================================================================
#  forward - Linux 端口转发管理工具  v3.0.0
#
#  一条命令搞定: 端口转发 + 防火墙后端兼容(iptables/nftables/firewalld)
#                + 开机自动恢复(systemd/OpenRC/SysVinit) + ip_forward 持久化
#
#  支持系统: Debian / Ubuntu / Linux Mint / Kali
#            RHEL / CentOS / Rocky / AlmaLinux / Fedora / Oracle Linux
#            Arch / Manjaro / openSUSE / SLES / Alpine / Gentoo
#
#  用法: forward                     交互菜单(推荐)
#        forward add -p tcp -l 8080 -d 10.0.0.5 -t 80
#        forward list | del 8080 | apply | status | clear
#        forward install            安装开机自启(重启后规则自动恢复)
#        forward --help             完整帮助
#
#  说明: 规则保存在 /etc/forward/rules.conf, 该文件是唯一事实来源,
#        apply 会按文件内容重建防火墙规则(只动自己的规则, 不碰 Docker/ufw)。
#
#  __FORWARD_TOOL__  本行是卸载时的身份标识: uninstall 会删除 PATH 中所有
#                    带此标识的 forward 副本, 避免"卸载后 forward 还能用"。
#===============================================================================

if [ -z "${BASH_VERSION:-}" ]; then
    echo "错误: 本脚本必须用 bash 运行, 请执行: bash $0" >&2
    exit 1
fi

set -u

#-------------------------------------------------------------------------------
# 常量与全局变量
#-------------------------------------------------------------------------------
readonly PROG="forward"
readonly VERSION="3.1.1"

# 所有路径都可用环境变量覆盖, 便于测试/容器内使用
readonly CONF_DIR="${FORWARD_CONF_DIR:-/etc/forward}"
readonly RULES_FILE="$CONF_DIR/rules.conf"
readonly APPLIED_FILE="$CONF_DIR/applied.conf"
readonly STATE_FILE="$CONF_DIR/state.conf"
readonly SYSCTL_DIR="${FORWARD_SYSCTL_DIR:-/etc/sysctl.d}"
readonly SYSCTL_FILE="$SYSCTL_DIR/zz-forward.conf"
readonly SYSCTL_CONF="${FORWARD_SYSCTL_CONF:-/etc/sysctl.conf}"
readonly SELF_BIN="${FORWARD_SELF_BIN:-/usr/local/sbin/forward}"
readonly SYSTEMD_UNIT="${FORWARD_UNIT_DIR:-/etc/systemd/system}/forward.service"
readonly INIT_SCRIPT="/etc/init.d/forward"

readonly NFT_TABLE="forward"       # nft 后端独占的表名: table ip forward
readonly NFT_TAG="forward"         # nft 规则注释, 用于识别自己的规则
readonly IPT_TAG="forward"         # iptables 规则注释前缀: forward:<端口>:<协议>

DRY_RUN=0
ASSUME_YES=0
QUIET=0
RAW=0
NO_COLOR_OPT=0

OPT_BACKEND=""      # 命令行 --backend
OPT_ZONE=""         # 命令行 --zone (firewalld)
OPT_PROTO=""        # add: 协议
OPT_LISTEN=""       # add: 监听端口
OPT_DEST=""         # add: 目标地址
OPT_DPORT=""        # add: 目标端口
OPT_MASQ=""         # add: 是否 SNAT(1/0)
OPT_CLEAR_RULES=0   # uninstall: 1 = 连内核里已生效的规则一起清 (--clear-rules)
OPT_ALL=0           # clear: 1 = 连不是本工具写入的规则一起清 (--all)
OPT_PURGE=0         # uninstall: 连 /etc/forward 配置一起删

BACKEND=""          # 解析后的后端
ZONE=""             # firewalld 区域
IPT_BIN="iptables"
IPT_W=""            # "-w 5" 或 ""
NO_COMMENT=0        # iptables 不支持 -m comment 时为 1
LOCAL_IPS_CACHE=""
POSITIONAL=()

C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""

#-------------------------------------------------------------------------------
# 输出
#-------------------------------------------------------------------------------
init_colors() {
    if [ "$NO_COLOR_OPT" = 1 ] || [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
        C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
    else
        C_RED=$'\033[31m'
        C_GRN=$'\033[32m'
        C_YEL=$'\033[33m'
        C_BLU=$'\033[36m'
        C_DIM=$'\033[2m'
        C_RST=$'\033[0m'
    fi
}

log()  { [ "$QUIET" = 1 ] && return 0; printf '%s\n' "$*"; }
info() { [ "$QUIET" = 1 ] && return 0; printf '%s[*]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { [ "$QUIET" = 1 ] && return 0; printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

#-------------------------------------------------------------------------------
# 基础工具
#-------------------------------------------------------------------------------
cmd_exists() { command -v "$1" >/dev/null 2>&1; }

need_root() {
    [ "${FORWARD_FAKE_ROOT:-0}" = 1 ] && return 0
    [ "$(id -u)" -eq 0 ] || die "需要 root 权限: 请使用 sudo $PROG ..."
}

# 读取 /etc/os-release 字段(不 source, 避免污染变量)
os_field() {
    [ -r /etc/os-release ] || { printf ''; return 0; }
    sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n 1 | sed 's/^"//; s/"$//'
}

distro_name() {
    local n
    n=$(os_field PRETTY_NAME)
    [ -z "$n" ] && n=$(os_field NAME)
    [ -z "$n" ] && n=$(sed -n 's/^DISTRIB_DESCRIPTION=//p' /etc/lsb-release 2>/dev/null | tr -d '"' | head -n 1)
    [ -z "$n" ] && n="未知发行版"
    printf '%s' "$n"
}

pkg_hint() {   # $1=包名
    local id
    id=$(os_field ID)
    case "$id" in
        debian|ubuntu|linuxmint|kali|raspbian|pop|elementary|zorin|devuan)
            printf 'apt-get update && apt-get install -y %s' "$1" ;;
        rhel|centos|rocky|almalinux|ol|fedora|amzn)
            if cmd_exists dnf; then printf 'dnf install -y %s' "$1"
            else printf 'yum install -y %s' "$1"; fi ;;
        arch|manjaro|endeavouros|garuda)
            printf 'pacman -S --noconfirm %s' "$1" ;;
        opensuse*|sles|suse)
            printf 'zypper install -y %s' "$1" ;;
        alpine)
            printf 'apk add %s' "$1" ;;
        gentoo)
            printf 'emerge -a %s' "$1" ;;
        *)
            printf '(请用本发行版的包管理器安装 %s)' "$1" ;;
    esac
}

init_system() {
    # 可用 FORWARD_INIT=systemd|openrc|sysvinit 强制指定(容器/非常规 init)
    if [ -n "${FORWARD_INIT:-}" ]; then
        printf '%s' "$FORWARD_INIT"
        return 0
    fi
    if [ -d /run/systemd/system ] && cmd_exists systemctl; then
        printf 'systemd'
    elif cmd_exists rc-update || [ -x /sbin/openrc-run ] || [ -x /sbin/rc-update ]; then
        printf 'openrc'
    elif cmd_exists update-rc.d || cmd_exists chkconfig; then
        printf 'sysvinit'
    else
        printf 'unknown'
    fi
}

#-------------------------------------------------------------------------------
# 配置目录 / 状态文件
#-------------------------------------------------------------------------------
ensure_conf_dir() {
    [ -d "$CONF_DIR" ] || mkdir -p "$CONF_DIR" 2>/dev/null || die "无法创建目录 $CONF_DIR"
    chmod 700 "$CONF_DIR" 2>/dev/null || true
    [ -f "$RULES_FILE" ] || : > "$RULES_FILE"
    chmod 600 "$RULES_FILE" 2>/dev/null || true
}

state_get() {
    [ -r "$STATE_FILE" ] || return 0
    sed -n "s/^$1=//p" "$STATE_FILE" 2>/dev/null | head -n 1
}

state_set() {   # key value
    local k="$1" v="$2" tmp
    [ -d "$CONF_DIR" ] || mkdir -p "$CONF_DIR" 2>/dev/null || return 1
    tmp=$(mktemp "$CONF_DIR/.state.XXXXXX" 2>/dev/null) || return 1
    if [ -f "$STATE_FILE" ]; then
        grep -v "^${k}=" "$STATE_FILE" > "$tmp" 2>/dev/null || true
    fi
    printf '%s=%s\n' "$k" "$v" >> "$tmp"
    if ! mv -f "$tmp" "$STATE_FILE"; then
        rm -f "$tmp" 2>/dev/null
        return 1
    fi
    chmod 600 "$STATE_FILE" 2>/dev/null || true
    return 0
}

#-------------------------------------------------------------------------------
# 校验 (修复: 前导零导致的八进制算术错误)
#-------------------------------------------------------------------------------
valid_port() {
    [[ "${1:-}" =~ ^[0-9]{1,5}$ ]] || return 1
    local n=$((10#$1))
    [ "$n" -ge 1 ] && [ "$n" -le 65535 ]
}

valid_proto() {
    case "${1:-}" in
        tcp|udp) return 0 ;;
        *) return 1 ;;
    esac
}

valid_ipv4() {
    local ip="${1:-}" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        [ "$((10#$o))" -le 255 ] || return 1
    done
    return 0
}

#-------------------------------------------------------------------------------
# 本机地址 / 规则模式
#    local      : 目标是本机回环或 0.0.0.0 -> REDIRECT(本机端口转发)
#    dnat_local : 目标就是本机某个网卡地址 -> DNAT + 放行 INPUT
#    dnat       : 目标是别的机器 -> DNAT + 放行 FORWARD
#-------------------------------------------------------------------------------
local_ips() {
    if [ -z "$LOCAL_IPS_CACHE" ]; then
        local raw=""
        if cmd_exists ip; then
            raw=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
        fi
        if [ -z "$raw" ] && cmd_exists hostname; then
            # -I 是 GNU/iproute2 扩展, busybox 只有 -i
            raw=$(hostname -I 2>/dev/null)
            [ -z "$raw" ] && raw=$(hostname -i 2>/dev/null)
        fi
        if [ -z "$raw" ] && cmd_exists ifconfig; then
            raw=$(ifconfig -a 2>/dev/null | awk '/inet (addr:)?[0-9]/ {
                       for (i = 1; i <= NF; i++)
                           if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) print $i
                       if ($(i+1) ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) print $(i+1)
                   }')
        fi
        LOCAL_IPS_CACHE=$(printf '%s\n' "$raw" | tr -s ' \t' '\n' \
            | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | tr '\n' ' ')
    fi
    printf '%s' "$LOCAL_IPS_CACHE"
}

ip_is_local() {
    case " $(local_ips) " in
        *" ${1:-} "*) return 0 ;;
    esac
    return 1
}

rule_mode() {   # $1=目标IP
    case "${1:-}" in
        127.*|0.0.0.0) printf 'local'; return 0 ;;
    esac
    if ip_is_local "${1:-}"; then
        printf 'dnat_local'
    else
        printf 'dnat'
    fi
}

#-------------------------------------------------------------------------------
# 规则文件解析 (统一格式: "proto lport dest_ip dport masq")
#-------------------------------------------------------------------------------
norm_file() {
    local f="${1:-}" line p lp dip dp extra masq
    [ -r "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}          # 容忍 CRLF
        case "$line" in
            ''|'#'*) continue ;;
        esac
        line=${line%%#*}            # 去掉行尾注释
        read -r p lp dip dp extra masq <<<"$line"
        [ -z "${p:-}" ] && continue
        if ! valid_proto "$p" || ! valid_port "${lp:-}" \
           || ! valid_ipv4 "${dip:-}" || ! valid_port "${dp:-}"; then
            warn "忽略无效规则行: $line"
            continue
        fi
        case "${extra:-}" in
            1|yes|true|on) masq=1 ;;
            *) masq=0 ;;
        esac
        # 下游可能用 head/grep -q 提前退出(会 SIGPIPE), 这类 "write error" 无意义, 直接吞掉
        printf '%s %s %s %s %s\n' "$p" "$((10#$lp))" "$dip" "$((10#$dp))" "$masq" 2>/dev/null
    done < "$f"
}

norm_rules() { norm_file "$RULES_FILE"; }

count_rules() { norm_rules | wc -l | tr -d ' '; }

rule_key_exists() {   # proto lport
    local p="$1" lp="$2" rp rlp rest
    while read -r rp rlp rest; do
        [ "$rp" = "$p" ] && [ "$rlp" = "$lp" ] && return 0
    done < <(norm_rules)
    return 1
}

rule_add() {   # proto lport dip dport masq
    local p="$1" lp="$2" dip="$3" dp="$4" m="${5:-0}" tmp rp rlp rdip rdp rm
    ensure_conf_dir
    tmp=$(mktemp "$CONF_DIR/.rules.XXXXXX" 2>/dev/null) || die "mktemp 失败"
    while read -r rp rlp rdip rdp rm; do
        if [ "$rp" = "$p" ] && [ "$rlp" = "$lp" ]; then
            continue
        fi
        printf '%s %s %s %s %s\n' "$rp" "$rlp" "$rdip" "$rdp" "$rm"
    done < <(norm_rules) > "$tmp"
    printf '%s %s %s %s %s\n' "$p" "$((10#$lp))" "$dip" "$((10#$dp))" "$m" >> "$tmp"
    mv -f "$tmp" "$RULES_FILE" || die "写入 $RULES_FILE 失败"
    chmod 600 "$RULES_FILE" 2>/dev/null || true
}

rule_del() {   # lport [proto]
    local lp="$1" p="${2:-}" tmp rp rlp rdip rdp rm n=0
    ensure_conf_dir
    tmp=$(mktemp "$CONF_DIR/.rules.XXXXXX" 2>/dev/null) || die "mktemp 失败"
    while read -r rp rlp rdip rdp rm; do
        if [ "$rlp" = "$lp" ] && { [ -z "$p" ] || [ "$p" = "$rp" ]; }; then
            n=$((n + 1))
            continue
        fi
        printf '%s %s %s %s %s\n' "$rp" "$rlp" "$rdip" "$rdp" "$rm"
    done < <(norm_rules) > "$tmp"
    mv -f "$tmp" "$RULES_FILE" || die "写入 $RULES_FILE 失败"
    chmod 600 "$RULES_FILE" 2>/dev/null || true
    [ "$n" -gt 0 ] || return 1
    return 0
}

backup_rules() {
    [ -s "$RULES_FILE" ] || return 0
    local b old
    b="$RULES_FILE.bak.$(date +%Y%m%d%H%M%S)"
    cp -f "$RULES_FILE" "$b" 2>/dev/null && info "规则已备份: $b"
    # 只保留最近 5 份备份, 避免 /etc/forward 无限增长
    old=$(ls -1t "$RULES_FILE".bak.* 2>/dev/null | tail -n +6)
    [ -n "$old" ] && printf '%s\n' "$old" | while IFS= read -r f; do rm -f "$f"; done
    return 0
}

#-------------------------------------------------------------------------------
# 后端探测
#-------------------------------------------------------------------------------
firewalld_running() {
    cmd_exists firewall-cmd || return 1
    firewall-cmd --state >/dev/null 2>&1
}

ipt_usable() {
    cmd_exists iptables || return 1
    iptables -w 5 -t nat -L -n >/dev/null 2>&1 && return 0
    iptables -t nat -L -n >/dev/null 2>&1 && return 0
    return 1
}

nft_usable() {
    cmd_exists nft || return 1
    nft list ruleset >/dev/null 2>&1
}

auto_backend() {
    # firewalld 优先: 它执行 --reload 时会清掉非永久 iptables 规则
    if firewalld_running; then printf 'firewalld'; return 0; fi
    if ipt_usable; then printf 'iptables'; return 0; fi
    if nft_usable; then printf 'nft'; return 0; fi
    printf ''
}

current_backend() {   # 非致命版: 仅用于展示/查询
    local b="${OPT_BACKEND:-${FORWARD_BACKEND:-$(state_get backend)}}"
    [ -z "$b" ] && b=auto
    if [ "$b" = auto ]; then
        auto_backend
    else
        printf '%s' "$b"
    fi
}

resolve_backend() {
    local b
    b="${OPT_BACKEND:-${FORWARD_BACKEND:-$(state_get backend)}}"
    [ -z "$b" ] && b=auto
    case "$b" in
        auto)
            BACKEND=$(auto_backend)
            if [ -z "$BACKEND" ]; then
                err "没有可用的防火墙工具, 请先安装:"
                err "  iptables: $(pkg_hint iptables)"
                err "  nftables: $(pkg_hint nftables)"
                return 1
            fi
            ;;
        iptables|nft|firewalld) BACKEND=$b ;;
        *) err "未知后端: $b (可选 auto|iptables|nft|firewalld)"; return 1 ;;
    esac
    case "$BACKEND" in
        iptables)
            ipt_usable || { err "iptables 不可用, 安装: $(pkg_hint iptables)"; return 1; }
            ;;
        nft)
            nft_usable || { err "nft 不可用, 安装: $(pkg_hint nftables)"; return 1; }
            ;;
        firewalld)
            firewalld_running || { err "firewalld 未运行, 无法使用 firewalld 后端"; return 1; }
            ;;
    esac
    if [ "$BACKEND" = iptables ] && firewalld_running; then
        warn "检测到 firewalld 正在运行: 它会用 --reload 清掉非永久 iptables 规则, 建议改用 --backend=firewalld"
    fi
    return 0
}

#-------------------------------------------------------------------------------
# iptables 后端
#-------------------------------------------------------------------------------
iptq() { "$IPT_BIN" ${IPT_W} "$@" 2>/dev/null; }          # 只读查询(始终真实执行)
iptm() {                                                   # 修改(遵循 --dry-run)
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] %s %s\n' "$IPT_BIN" "$*"
        return 0
    fi
    "$IPT_BIN" ${IPT_W} "$@"
}

set_comment() {   # 设置 IPT_C_ARGS
    if [ "$NO_COMMENT" = 1 ]; then
        IPT_C_ARGS=()
    else
        IPT_C_ARGS=(-m comment --comment "$1")
    fi
}
IPT_C_ARGS=()

# 幂等添加: ipt_add <table> <A|I> <chain> <spec...>
ipt_add() {
    local tbl="$1" act="$2" ch="$3"
    shift 3
    local spec=("$@")
    if [ "$NO_COMMENT" = 1 ]; then
        if iptq -t "$tbl" -C "$ch" "${spec[@]}" >/dev/null 2>&1; then
            return 0
        fi
    fi
    if [ "$act" = I ]; then
        iptm -t "$tbl" -I "$ch" 1 "${spec[@]}"
    else
        iptm -t "$tbl" -A "$ch" "${spec[@]}"
    fi
}

ipt_init() {
    cmd_exists iptables || { err "未找到 iptables, 安装: $(pkg_hint iptables)"; return 1; }
    IPT_BIN=iptables
    if "$IPT_BIN" -w 5 -t nat -L -n >/dev/null 2>&1; then
        IPT_W="-w 5"        # xtables 锁等待 5 秒, 避免与 Docker/ufw 抢锁报错
    elif "$IPT_BIN" -w -t nat -L -n >/dev/null 2>&1; then
        IPT_W="-w"          # 老版本只支持不带超时的 -w
    else
        IPT_W=""
    fi
    if cmd_exists modprobe; then
        modprobe -q nf_conntrack 2>/dev/null || true
        modprobe -q nf_nat 2>/dev/null || true
        modprobe -q iptable_nat 2>/dev/null || true
        modprobe -q xt_comment 2>/dev/null || true
    fi
    # 探测 -m comment 是否可用(dry-run 不动系统)
    NO_COMMENT=0
    if [ "$DRY_RUN" = 1 ]; then
        return 0
    fi
    if ! iptq -t nat -A PREROUTING -p tcp --dport 65535 \
            -m comment --comment "$IPT_TAG:probe" -j RETURN; then
        NO_COMMENT=1
        warn "内核缺少 xt_comment 模块: 规则将不带注释标记, 清空功能将依赖快照文件"
    else
        iptq -t nat -D PREROUTING -p tcp --dport 65535 \
            -m comment --comment "$IPT_TAG:probe" -j RETURN || true
    fi
    return 0
}

# 清掉自己加过的规则(按注释标记识别, 不碰别人的规则)
# $3 可指定别的标记(迁移旧版本规则时用)
# 用 "行号删除": 注释里可能带空格/引号, 从 -S 重新拼参数会拆词导致
#   "Bad argument `old'"(实测), 而 -D 链名 行号 不受影响。
SWEPT_COUNT=0
ipt_sweep_chain() {
    local tbl="$1" ch="$2" tag="${3:-$IPT_TAG}" num guard=0
    SWEPT_COUNT=0
    [ "$NO_COMMENT" = 1 ] && return 0
    iptq -t "$tbl" -L "$ch" -n >/dev/null 2>&1 || return 0
    while :; do
        num=$(iptq -t "$tbl" -L "$ch" -n --line-numbers 2>/dev/null | awk -v tag="${tag}:" '
            $1 ~ /^[0-9]+$/ && index($0, tag) { print $1; exit }')
        [ -z "$num" ] && break
        guard=$((guard + 1))
        if [ "$guard" -gt 2000 ]; then
            warn "清理 $tbl/$ch 时超过上限, 已中止"
            break
        fi
        iptm -t "$tbl" -D "$ch" "$num" || break
        SWEPT_COUNT=$((SWEPT_COUNT + 1))
    done
}

ipt_sweep() {
    local t=0
    ipt_sweep_chain nat PREROUTING;      t=$((t + SWEPT_COUNT))
    ipt_sweep_chain nat POSTROUTING;     t=$((t + SWEPT_COUNT))
    ipt_sweep_chain filter FORWARD;      t=$((t + SWEPT_COUNT))
    ipt_sweep_chain filter INPUT;        t=$((t + SWEPT_COUNT))
    SWEPT_COUNT=$t
}

# 为一条规则生成 iptables 规则(适用于 apply / clear 两个方向)
ipt_rule_specs() {   # proto lport dip dport masq -> 每行输出 "table|action|chain|args..."
    local p="$1" lp="$2" dip="$3" dp="$4" m="$5" mode c
    mode=$(rule_mode "$dip")
    c="$IPT_TAG:$lp:$p"
    if [ "$mode" = local ]; then
        printf 'nat|A|PREROUTING|-p %s --dport %s -m comment --comment %s -j REDIRECT --to-ports %s\n' \
            "$p" "$lp" "$c" "$dp"
        printf 'filter|I|INPUT|-p %s --dport %s -m comment --comment %s -j ACCEPT\n' \
            "$p" "$dp" "$c"
    else
        printf 'nat|A|PREROUTING|-p %s --dport %s -m comment --comment %s -j DNAT --to-destination %s:%s\n' \
            "$p" "$lp" "$c" "$dip" "$dp"
        if [ "$mode" = dnat_local ]; then
            printf 'filter|I|INPUT|-p %s --dport %s -m comment --comment %s -j ACCEPT\n' \
                "$p" "$dp" "$c"
        else
            printf 'filter|I|FORWARD|-p %s -d %s --dport %s -m comment --comment %s -j ACCEPT\n' \
                "$p" "$dip" "$dp" "$c"
            # 回程方向: 服务端回来时已经过 conntrack 还原, 源是 DIP:DP
            printf 'filter|I|FORWARD|-p %s -s %s --sport %s -m comment --comment %s -j ACCEPT\n' \
                "$p" "$dip" "$dp" "$c"
            if [ "$m" = 1 ]; then
                printf 'nat|A|POSTROUTING|-p %s -d %s --dport %s -m comment --comment %s -j MASQUERADE\n' \
                    "$p" "$dip" "$dp" "$c"
            fi
        fi
    fi
}

ipt_apply() {
    local p lp dip dp m mode c rc=0 spec tbl act ch rest
    ipt_init || return 1
    ipt_sweep

    while read -r p lp dip dp m; do
        set_comment "$IPT_TAG:$lp:$p"
        mode=$(rule_mode "$dip")
        if [ "$mode" = local ]; then
            ipt_add nat A PREROUTING -p "$p" --dport "$lp" \
                "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                -j REDIRECT --to-ports "$dp" || { err "添加 REDIRECT 规则失败: $p/$lp"; rc=1; }
            ipt_add filter I INPUT -p "$p" --dport "$dp" \
                "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                -j ACCEPT || { err "放行 INPUT 失败: $p/$dp"; rc=1; }
        else
            ipt_add nat A PREROUTING -p "$p" --dport "$lp" \
                "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                -j DNAT --to-destination "$dip:$dp" || { err "添加 DNAT 规则失败: $p/$lp"; rc=1; }
            if [ "$mode" = dnat_local ]; then
                ipt_add filter I INPUT -p "$p" --dport "$dp" \
                    "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                    -j ACCEPT || { err "放行 INPUT 失败: $p/$dp"; rc=1; }
            else
                ipt_add filter I FORWARD -p "$p" -d "$dip" --dport "$dp" \
                    "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                    -j ACCEPT || { err "放行 FORWARD 失败: $p/$lp"; rc=1; }
                ipt_add filter I FORWARD -p "$p" -s "$dip" --sport "$dp" \
                    "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                    -j ACCEPT || { err "放行 FORWARD(回程) 失败: $p/$lp"; rc=1; }
                if [ "$m" = 1 ]; then
                    ipt_add nat A POSTROUTING -p "$p" -d "$dip" --dport "$dp" \
                        "${IPT_C_ARGS[@]+"${IPT_C_ARGS[@]}"}" \
                        -j MASQUERADE || { err "添加 MASQUERADE 失败: $p/$lp"; rc=1; }
                fi
            fi
        fi
    done < <(norm_rules)
    return $rc
}

ipt_clear() {
    ipt_init || return 1
    if [ "$NO_COMMENT" = 1 ]; then
        warn "无法按注释识别规则, 改用快照逐条删除"
        local p lp dip dp m spec tbl act ch rest
        while read -r p lp dip dp m; do
            while IFS='|' read -r tbl act ch rest; do
                [ -z "${tbl:-}" ] && continue
                [ -z "${rest:-}" ] && continue
                # 快照里的规格可能被重复添加过, 反复删除直到 -D 失败
                local guard=0
                while [ "$guard" -lt 2000 ]; do
                    guard=$((guard + 1))
                    # shellcheck disable=SC2086
                    iptq -t "$tbl" -D "$ch" $rest >/dev/null 2>&1 || break
                done
            done < <(ipt_rule_specs "$p" "$lp" "$dip" "$dp" "$m" | sed 's/ -m comment --comment [^ ]*//')
        done < <(norm_file "$APPLIED_FILE")
    else
        ipt_sweep
    fi
    return 0
}

#-------------------------------------------------------------------------------
# nftables 后端 (独占表 ip forward, 每次全量原子重建)
#-------------------------------------------------------------------------------
nftm() {   # 修改(遵循 --dry-run)
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] nft %s\n' "$*"
        return 0
    fi
    nft "$@"
}

nft_init() {
    cmd_exists nft || { err "未找到 nft, 安装: $(pkg_hint nftables)"; return 1; }
    if cmd_exists modprobe; then
        modprobe -q nf_tables 2>/dev/null || true
        modprobe -q nf_nat 2>/dev/null || true
        modprobe -q nf_conntrack 2>/dev/null || true
    fi
    nft list ruleset >/dev/null 2>&1 || { err "nft 不可用(需要 root 且内核支持 nf_tables)"; return 1; }
    return 0
}

# 找出所有 filter 类 base chain (hook forward / hook input)
# 优先用 nft list chains; 个别版本/空表时回退 nft list ruleset, 输出结构一致
nft_hook_chains() {   # $1 = forward|input
    local out
    out=$(nft list chains 2>/dev/null)
    if [ -z "$out" ]; then
        out=$(nft list ruleset 2>/dev/null)
    fi
    printf '%s\n' "$out" | awk -v hook="$1" '
        /^table / {
            fam = $2; tbl = $3
            sub(/[[:space:]]*\{[[:space:]]*$/, "", tbl)
            chain = ""
            next
        }
        /^[[:space:]]+chain / {
            chain = $2
            sub(/[[:space:]]*\{[[:space:]]*$/, "", chain)
            next
        }
        /^[[:space:]]+type .*hook / {
            if (chain != "" && index($0, "hook " hook " ") > 0) {
                if (fam == "ip" || fam == "inet") print fam, tbl, chain
            }
            chain = ""
        }
    '
}

# 删除指定链里我们加过的规则(按 comment forward 识别; 不同 nft 版本对 comment 的引号处理不同, 故不做严格匹配)
nft_purge_chain() {   # fam tbl chain
    local fam="$1" tbl="$2" ch="$3" h
    for h in $(nft -a list chain "$fam" "$tbl" "$ch" 2>/dev/null \
                | awk '/comment/ && /forward/ {print $NF}'); do
        case "$h" in ''|*[!0-9]*) continue ;; esac
        nftm delete rule "$fam" "$tbl" "$ch" handle "$h" 2>/dev/null || true
    done
}

nft_clear() {
    nft_init || return 1
    if nft list table ip "$NFT_TABLE" >/dev/null 2>&1; then
        nftm delete table ip "$NFT_TABLE" || { err "删除 nft 表 ip $NFT_TABLE 失败"; return 1; }
    fi
    nft_clear_hooks
    return 0
}

nft_clear_hooks() {
    local fam tbl ch
    { nft_hook_chains forward; nft_hook_chains input; } | sort -u | \
    while read -r fam tbl ch; do
        [ -z "${fam:-}" ] && continue
        nft_purge_chain "$fam" "$tbl" "$ch"
    done
}

# 在既有的 forward/input 链里放行(这是纯 nft 系统上转发能通的关键)
# 结果记录到全局 NFT_HOOK_INSERTED (dry-run 时只打印命令)
NFT_HOOK_INSERTED=0
nft_sync_hook() {   # $1 = forward|input
    local hook="$1" chains fam tbl ch p lp dip dp m mode
    NFT_HOOK_INSERTED=0
    chains=$(nft_hook_chains "$hook")
    if [ -z "$chains" ]; then
        return 0
    fi
    while read -r fam tbl ch; do
        [ -z "${fam:-}" ] && continue
        nft_purge_chain "$fam" "$tbl" "$ch"
        if [ "$hook" = forward ]; then
            while read -r p lp dip dp m; do
                [ "$(rule_mode "$dip")" = local ] && continue
                if nftm insert rule "$fam" "$tbl" "$ch" \
                        ip daddr "$dip" "$p" dport "$dp" accept comment "$NFT_TAG" 2>/dev/null; then
                    NFT_HOOK_INSERTED=$((NFT_HOOK_INSERTED + 1))
                fi
                # 回程方向(conntrack 还原后源地址是 DIP:DP)
                if nftm insert rule "$fam" "$tbl" "$ch" \
                        ip saddr "$dip" "$p" sport "$dp" accept comment "$NFT_TAG" 2>/dev/null; then
                    NFT_HOOK_INSERTED=$((NFT_HOOK_INSERTED + 1))
                fi
            done < <(norm_rules)
        else
            while read -r p lp dip dp m; do
                mode=$(rule_mode "$dip")
                [ "$mode" = dnat ] && continue
                if nftm insert rule "$fam" "$tbl" "$ch" \
                        "$p" dport "$dp" accept comment "$NFT_TAG" 2>/dev/null; then
                    NFT_HOOK_INSERTED=$((NFT_HOOK_INSERTED + 1))
                fi
            done < <(norm_rules)
        fi
    done <<<"$chains"
    return 0
}

# 人类可读的完整规则集(用于 --dry-run 预览与日志)
nft_preview() {
    local p lp dip dp m mode
    printf '# 由 forward 生成, 规则来源 %s\n' "$RULES_FILE"
    printf 'table ip %s {\n' "$NFT_TABLE"
    printf '\tchain prerouting {\n'
    printf '\t\ttype nat hook prerouting priority -100; policy accept;\n'
    while read -r p lp dip dp m; do
        mode=$(rule_mode "$dip")
        if [ "$mode" = local ]; then
            printf '\t\t%s dport %s redirect to :%s\n' "$p" "$lp" "$dp"
        else
            printf '\t\t%s dport %s dnat to %s:%s\n' "$p" "$lp" "$dip" "$dp"
        fi
    done < <(norm_rules)
    printf '\t}\n'
    printf '\tchain postrouting {\n'
    printf '\t\ttype nat hook postrouting priority 100; policy accept;\n'
    while read -r p lp dip dp m; do
        [ "$m" = 1 ] || continue
        [ "$(rule_mode "$dip")" = dnat ] || continue
        printf '\t\tip daddr %s %s dport %s masquerade\n' "$dip" "$p" "$dp"
    done < <(norm_rules)
    printf '\t}\n'
    printf '}\n'
}

# 真正下发的 nft 脚本: 表不存在时先建表建链, 然后 flush + 逐条 add rule。
# 关键: 不重复声明已存在的链(有的 nft 版本会报 "File exists"), 整份脚本一次 nft -f 提交。
nft_batch() {
    local p lp dip dp m mode
    # 表或链缺失时先补建(链被手工删掉的情况也覆盖)
    if ! nft list table ip "$NFT_TABLE" >/dev/null 2>&1 \
       || ! nft list chain ip "$NFT_TABLE" prerouting >/dev/null 2>&1 \
       || ! nft list chain ip "$NFT_TABLE" postrouting >/dev/null 2>&1; then
        printf 'table ip %s {\n' "$NFT_TABLE"
        printf '\tchain prerouting { type nat hook prerouting priority -100; policy accept; }\n'
        printf '\tchain postrouting { type nat hook postrouting priority 100; policy accept; }\n'
        printf '}\n'
    fi
    printf 'flush table ip %s\n' "$NFT_TABLE"
    while read -r p lp dip dp m; do
        mode=$(rule_mode "$dip")
        if [ "$mode" = local ]; then
            printf 'add rule ip %s prerouting %s dport %s redirect to :%s\n' \
                "$NFT_TABLE" "$p" "$lp" "$dp"
        else
            printf 'add rule ip %s prerouting %s dport %s dnat to %s:%s\n' \
                "$NFT_TABLE" "$p" "$lp" "$dip" "$dp"
        fi
    done < <(norm_rules)
    while read -r p lp dip dp m; do
        [ "$m" = 1 ] || continue
        [ "$(rule_mode "$dip")" = dnat ] || continue
        printf 'add rule ip %s postrouting ip daddr %s %s dport %s masquerade\n' \
            "$NFT_TABLE" "$dip" "$p" "$dp"
    done < <(norm_rules)
}

nft_apply() {
    local f rc=0 inserted
    nft_init || return 1

    if [ "$DRY_RUN" = 1 ]; then
        info "[dry-run] 将执行的 nft 规则集:"
        nft_preview | sed 's/^/    /'
        nft_sync_hook forward
        nft_sync_hook input
        return 0
    fi

    f=$(mktemp 2>/dev/null) || die "mktemp 失败"
    nft_batch > "$f"
    if ! nft -f "$f"; then
        err "nft 应用规则失败(见上面的错误信息)"
        rc=1
    fi
    rm -f "$f"
    [ "$rc" -eq 0 ] || return "$rc"

    # 在既有的 forward/input 链里放行(纯 nft 系统上转发能通的关键)
    nft_sync_hook forward
    inserted=$NFT_HOOK_INSERTED
    nft_sync_hook input
    if [ "$inserted" -eq 0 ] && [ "$(count_rules)" -gt 0 ]; then
        info "未发现 hook forward 的过滤链(系统默认放行转发), 无需额外放行"
    fi
    return 0
}

#-------------------------------------------------------------------------------
# firewalld 后端 (永久配置 + reload, 由 firewalld 自己持久化)
#-------------------------------------------------------------------------------
fw_perm() {   # 修改(遵循 --dry-run); 成功时静默, 失败时把原因打到 stderr
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] firewall-cmd --permanent %s\n' "$*"
        return 0
    fi
    local out
    if ! out=$(firewall-cmd --permanent "$@" 2>&1); then
        [ -n "$out" ] && printf '%s\n' "$out" >&2
        return 1
    fi
    return 0
}

fw_query() { firewall-cmd "$@" >/dev/null 2>&1; }

fw_init() {
    cmd_exists firewall-cmd || { err "未找到 firewall-cmd, 安装: $(pkg_hint firewalld)"; return 1; }
    firewalld_running || { err "firewalld 未运行, 请先 systemctl start firewalld"; return 1; }
    ZONE="${OPT_ZONE:-${FORWARD_ZONE:-$(firewall-cmd --get-default-zone 2>/dev/null)}}"
    [ -z "$ZONE" ] && ZONE=public
    if ! firewall-cmd --get-zones 2>/dev/null | tr ' ' '\n' | grep -qx "$ZONE"; then
        if [ -n "${OPT_ZONE:-}${FORWARD_ZONE:-}" ]; then
            err "指定的 firewalld 区域不存在: $ZONE"
            return 1
        fi
        warn "区域 $ZONE 不存在, 回退到 public"
        ZONE=public
    fi
    return 0
}

fw_spec() {   # proto lport dip dport -> 输出 forward-port 规格
    local p="$1" lp="$2" dip="$3" dp="$4" mode
    mode=$(rule_mode "$dip")
    if [ "$mode" = local ]; then
        printf 'port=%s:proto=%s:toport=%s' "$lp" "$p" "$dp"
    else
        printf 'port=%s:proto=%s:toport=%s:toaddr=%s' "$lp" "$p" "$dp" "$dip"
    fi
}

fw_remove_file() {   # 按给定规则文件移除永久规则
    local f="$1" p lp dip dp m mode spec moved=0 rc=0
    [ -r "$f" ] || return 0
    while read -r p lp dip dp m; do
        [ -n "${p:-}" ] || continue
        mode=$(rule_mode "$dip")
        spec=$(fw_spec "$p" "$lp" "$dip" "$dp")
        if fw_query --permanent --zone="$ZONE" --query-forward-port="$spec"; then
            fw_perm --zone="$ZONE" --remove-forward-port="$spec" || rc=1
            moved=1
        fi
        if [ "$mode" = local ] \
           && fw_query --permanent --zone="$ZONE" --query-port="$dp/$p"; then
            fw_perm --zone="$ZONE" --remove-port="$dp/$p" || rc=1
            moved=1
        fi
    done < "$f"
    return "$rc"
}

fw_apply() {
    local p lp dip dp m mode spec rc=0
    fw_init || return 1
    # 1) 先移除上次的规则(快照)
    fw_remove_file "$APPLIED_FILE"
    # 2) 再按当前配置添加
    while read -r p lp dip dp m; do
        mode=$(rule_mode "$dip")
        spec=$(fw_spec "$p" "$lp" "$dip" "$dp")
        if ! fw_query --permanent --zone="$ZONE" --query-forward-port="$spec"; then
            fw_perm --zone="$ZONE" --add-forward-port="$spec" \
                || { err "添加 forward-port 失败: $spec"; rc=1; }
        fi
        if [ "$mode" = local ]; then
            if ! fw_query --permanent --zone="$ZONE" --query-port="$dp/$p"; then
                fw_perm --zone="$ZONE" --add-port="$dp/$p" \
                    || { err "放行本机端口失败: $dp/$p (规则已加, 但本机端口可能被拦)"; rc=1; }
            fi
        else
            # firewalld 的 forward-port 指向其它主机时要求开启地址伪装
            if ! fw_query --permanent --zone="$ZONE" --query-masquerade; then
                fw_perm --zone="$ZONE" --add-masquerade \
                    || { err "开启 masquerade 失败, 目标机可能收不到回程流量"; rc=1; }
            fi
        fi
    done < <(norm_rules)
    # 3) 生效
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] firewall-cmd --reload\n'
    else
        firewall-cmd --reload >/dev/null 2>&1 || { err "firewall-cmd --reload 失败"; rc=1; }
    fi
    return $rc
}

fw_clear() {
    fw_init || return 1
    local rc=0
    fw_remove_file "$RULES_FILE" || rc=1
    fw_remove_file "$APPLIED_FILE" || rc=1
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] firewall-cmd --reload\n'
    else
        firewall-cmd --reload >/dev/null 2>&1 \
            || { err "firewall-cmd --reload 失败，永久规则已删除但未立即生效"; rc=1; }
    fi
    return "$rc"
}

#-------------------------------------------------------------------------------
# ip_forward 开启 + 持久化
#-------------------------------------------------------------------------------
persist_ip_forward() {
    local want="net.ipv4.ip_forward = 1"
    # 1) sysctl.d: 用 zz- 前缀, 保证在 /etc/sysctl.d/99-sysctl.conf 之后加载
    if ! grep -qs '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1' "$SYSCTL_FILE" 2>/dev/null; then
        if mkdir -p "$SYSCTL_DIR" 2>/dev/null; then
            {
                printf '# 由 forward 生成: 端口转发需要开启 IPv4 路由转发\n'
                printf '%s\n' "$want"
            } > "$SYSCTL_FILE" 2>/dev/null \
                && { chmod 644 "$SYSCTL_FILE" 2>/dev/null || true; } \
                || warn "写入 $SYSCTL_FILE 失败"
        fi
    fi

    # 2) /etc/sysctl.conf: 修正 =0 的旧值 / 补齐缺失项
    if [ -w "$SYSCTL_CONF" ] || [ ! -e "$SYSCTL_CONF" ]; then
        if [ ! -e "$SYSCTL_CONF" ]; then
            printf '%s\n' "$want" > "$SYSCTL_CONF" 2>/dev/null || true
        elif grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$SYSCTL_CONF"; then
            # 容忍 "= 0" / "=00" / "= 0  # 注释" 等写法
            if awk '/^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=/ {
                        sub(/#.*/, "");
                        if ($0 ~ /=[[:space:]]*0+[[:space:]]*$/) found = 1
                     }
                     END { exit(found ? 0 : 1) }' "$SYSCTL_CONF" 2>/dev/null; then
                local tmp
                tmp=$(mktemp "$(dirname "$SYSCTL_CONF")/.sysctl.XXXXXX" 2>/dev/null) || return 0
                cp -f "$SYSCTL_CONF" "$SYSCTL_CONF.forward.bak" 2>/dev/null || true
                awk 'BEGIN{ done=0 }
                     /^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=/ {
                         if (!done) { print "net.ipv4.ip_forward = 1"; done=1 }
                         next
                     }
                     { print }' "$SYSCTL_CONF" > "$tmp" 2>/dev/null \
                    && mv -f "$tmp" "$SYSCTL_CONF" 2>/dev/null \
                    && info "已修正 $SYSCTL_CONF 中的 net.ipv4.ip_forward=0"
            fi
        else
            printf '\n%s\n' "$want" >> "$SYSCTL_CONF" 2>/dev/null || true
        fi
    fi
    return 0
}

ensure_ip_forward() {
    local cur
    cur=$(sysctl -n net.ipv4.ip_forward 2>/dev/null | tr -d ' ')
    if [ "$cur" != "1" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            printf '  [dry-run] sysctl -w net.ipv4.ip_forward=1\n'
        else
            sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
                || warn "开启 ip_forward 失败(可能是容器环境)"
        fi
    fi
    [ "$DRY_RUN" = 1 ] || persist_ip_forward
    return 0
}

#-------------------------------------------------------------------------------
# apply / clear / list / test / status
#-------------------------------------------------------------------------------
save_applied() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ -d "$CONF_DIR" ] || mkdir -p "$CONF_DIR" 2>/dev/null
    norm_rules > "$APPLIED_FILE" 2>/dev/null || true
    chmod 600 "$APPLIED_FILE" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# 诊断: 规则"明明有但识别不到"时, 把环境、配置、后端原始输出全打出来
#-------------------------------------------------------------------------------
do_doctor() {
    need_root
    invalidate_rules_cache
    local b init zone
    init=$(init_system)
    b=$(current_backend)

    log "==== 环境 ===="
    printf '  %-12s %s\n' "版本"       "$VERSION"
    printf '  %-12s %s\n' "发行版"     "$(distro_name)"
    printf '  %-12s %s\n' "内核"       "$(uname -r 2>/dev/null)"
    printf '  %-12s %s\n' "init"       "${init:-未识别}"
    printf '  %-12s %s\n' "后端"       "${b:-未探测到}"
    printf '  %-12s %s\n' "ip_forward" "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?')"
    printf '  %-12s %s\n' "配置目录"   "$CONF_DIR"
    printf '  %-12s %s\n' "开机自启"   "$(persist_enabled && echo 已启用 || echo 未启用)"

    log "==== 解析出的规则 (proto lport dest kind) ===="
    if [ -n "$(installed_rules)" ]; then
        installed_rules | sed 's/^/  /'
    else
        printf '  (空)\n'
    fi

    log "==== 配置: $RULES_FILE ===="
    if [ -f "$RULES_FILE" ]; then sed 's/^/  /' "$RULES_FILE"; else printf '  (文件不存在)\n'; fi
    log "==== 快照: $APPLIED_FILE ===="
    if [ -f "$APPLIED_FILE" ]; then sed 's/^/  /' "$APPLIED_FILE"; else printf '  (文件不存在)\n'; fi
    log "==== 状态: $STATE_FILE ===="
    if [ -f "$STATE_FILE" ]; then sed 's/^/  /' "$STATE_FILE"; else printf '  (文件不存在)\n'; fi

    log "==== 后端原始输出 ===="
    case "$b" in
        iptables)
            printf '  $ iptables -t nat -S\n'
            iptq -t nat -S 2>&1 | sed 's/^/    /'
            printf '  $ iptables -S FORWARD\n'
            iptq -S FORWARD 2>&1 | sed 's/^/    /'
            ;;
        nft)
            printf '  $ nft list table ip %s\n' "$NFT_TABLE"
            nft list table ip "$NFT_TABLE" 2>&1 | sed 's/^/    /'
            printf '  $ nft list chains\n'
            nft list chains 2>&1 | sed 's/^/    /'
            ;;
        firewalld)
            zone=$(fw_zone)
            printf '  $ firewall-cmd --zone=%s --list-all\n' "$zone"
            firewall-cmd --zone="$zone" --list-all 2>&1 | sed 's/^/    /'
            ;;
        *)
            printf '  (没有可用后端: 检查 iptables / nft / firewall-cmd 是否安装可用)\n'
            ;;
    esac

    log "==== 自启状态 ===="
    case "$init" in
        systemd)
            systemctl status forward.service --no-pager 2>&1 | sed 's/^/  /' | head -n 12
            ;;
        openrc)
            rc-service forward status 2>&1 | sed 's/^/  /'
            ;;
        sysvinit)
            ls -l /etc/rc2.d/S??forward /etc/rc3.d/S??forward /etc/rc.d/rc3.d/S??forward 2>/dev/null \
                | sed 's/^/  /' || printf '  (没有 rc 链接)\n'
            ;;
        *)
            printf '  (未识别的 init)\n'
            ;;
    esac
    return 0
}

#-------------------------------------------------------------------------------
# 旧版本(命令名 portfwd)迁移
#   旧版把规则放在 /etc/portfwd、nft 用 table ip portfwd、iptables 注释是 portfwd:
#   升级后这些规则会变成"没有工具管"的孤儿, 所以这里一次性收编: 配置搬过来、旧规则删掉。
#   路径都可用 FORWARD_LEGACY_* 覆盖(测试用), 迁移只做一次(state 里记 legacy=done)。
#-------------------------------------------------------------------------------
LEGACY_DIR="${FORWARD_LEGACY_DIR:-$(dirname "$CONF_DIR")/portfwd}"
LEGACY_BIN="${FORWARD_LEGACY_BIN:-/usr/local/sbin/portfwd}"
LEGACY_NFT_TABLE="${FORWARD_LEGACY_NFT-portfwd}"
LEGACY_UNIT="${FORWARD_LEGACY_UNIT:-/etc/systemd/system/portfwd.service}"
LEGACY_INIT="${FORWARD_LEGACY_INIT:-/etc/init.d/portfwd}"

legacy_sweep_one() {   # table chain
    ipt_sweep_chain "$1" "$2" "portfwd"
    [ "$SWEPT_COUNT" -gt 0 ]
}

# 旧版残留是否还在(即使之前迁移过, 也允许再清理一次; 比如后来手工跑过旧脚本)
legacy_artifacts_exist() {
    [ -f "$LEGACY_BIN" ] && return 0
    [ -f "$LEGACY_UNIT" ] && return 0
    [ -f "$LEGACY_INIT" ] && return 0
    if [ -d "$LEGACY_DIR" ] && [ "$LEGACY_DIR" != "$CONF_DIR" ] && [ -s "$LEGACY_DIR/rules.conf" ]; then
        return 0
    fi
    if [ -n "$LEGACY_NFT_TABLE" ] && cmd_exists nft \
       && nft list table ip "$LEGACY_NFT_TABLE" >/dev/null 2>&1; then
        return 0
    fi
    if cmd_exists iptables && iptables -t nat -S 2>/dev/null | grep -q -- "--comment \"portfwd:"; then
        return 0
    fi
    return 1
}

legacy_migrate() {
    [ "${FORWARD_NO_LEGACY:-0}" = 1 ] && return 0
    if [ "$(state_get legacy)" = "done" ] && ! legacy_artifacts_exist; then
        return 0
    fi
    local moved=0

    # 1) 旧配置文件
    if [ -d "$LEGACY_DIR" ] && [ "$LEGACY_DIR" != "$CONF_DIR" ]; then
        ensure_conf_dir >/dev/null 2>&1 || true
        if [ -s "$LEGACY_DIR/rules.conf" ] && [ ! -s "$RULES_FILE" ]; then
            cp -f "$LEGACY_DIR/rules.conf" "$RULES_FILE" 2>/dev/null && {
                warn "已迁移旧配置: $LEGACY_DIR/rules.conf -> $RULES_FILE"
                moved=1
            }
        fi
        local f
        for f in applied.conf state.conf; do
            if [ -s "$LEGACY_DIR/$f" ] && [ ! -s "$CONF_DIR/$f" ]; then
                cp -f "$LEGACY_DIR/$f" "$CONF_DIR/$f" 2>/dev/null || true
            fi
        done
    fi

    # 2) 旧 nft 表 table ip portfwd
    if [ -n "$LEGACY_NFT_TABLE" ] && cmd_exists nft \
       && nft list table ip "$LEGACY_NFT_TABLE" >/dev/null 2>&1; then
        if [ "$DRY_RUN" = 1 ]; then
            printf '  [dry-run] nft delete table ip %s\n' "$LEGACY_NFT_TABLE"
        else
            nft delete table ip "$LEGACY_NFT_TABLE" 2>/dev/null || true
            warn "已删除旧版 nft 表 ip $LEGACY_NFT_TABLE"
        fi
        moved=1
    fi

    # 3) 旧 iptables 规则(注释为 portfwd:...)
    if cmd_exists iptables; then
        ipt_init >/dev/null 2>&1 || true
        legacy_sweep_one nat PREROUTING && moved=1
        legacy_sweep_one nat POSTROUTING && moved=1
        legacy_sweep_one filter FORWARD && moved=1
        legacy_sweep_one filter INPUT && moved=1
    fi

    # 4) 旧命令与自启文件
    if [ -f "$LEGACY_BIN" ] && [ "$LEGACY_BIN" != "$SELF_BIN" ]; then
        rm -f "$LEGACY_BIN" 2>/dev/null && { warn "已删除旧版命令 $LEGACY_BIN"; moved=1; }
    fi
    if [ -f "$LEGACY_UNIT" ]; then
        systemctl disable "$(basename "$LEGACY_UNIT")" >/dev/null 2>&1 || true
        rm -f "$LEGACY_UNIT" && {
            systemctl daemon-reload >/dev/null 2>&1 || true
            warn "已移除旧版自启单元 $LEGACY_UNIT"
            moved=1
        }
    fi
    if [ -f "$LEGACY_INIT" ]; then
        rm -f "$LEGACY_INIT" 2>/dev/null && moved=1
    fi
    rm -f /etc/rc2.d/S??portfwd /etc/rc3.d/S??portfwd \
          /etc/rc5.d/S??portfwd /etc/rc.d/rc3.d/S??portfwd 2>/dev/null || true

    ensure_conf_dir >/dev/null 2>&1 || true
    state_set legacy done >/dev/null 2>&1 || true
    [ "$moved" = 1 ] && ok "旧版(portfwd)残留已清理" || info "无旧版本残留"
    return 0
}

# 切换后端时清理"另一个后端"里我们自己写下的规则。
# 否则同一入口端口会被 DNAT 两遍(iptables 与 nft 各一条), 或者旧后端的放行规则一直残留。
cleanup_other_backends() {
    local want="$1"
    if [ "$want" != iptables ] && [ -s "$APPLIED_FILE" ] && cmd_exists iptables; then
        if ipt_clear >/dev/null 2>&1 && [ "${SWEPT_COUNT:-0}" -gt 0 ]; then
            info "已清理 iptables 后端留下的 ${SWEPT_COUNT} 条规则"
        fi
    fi
    if [ "$want" != nft ] && cmd_exists nft; then
        if nft list table ip "$NFT_TABLE" >/dev/null 2>&1; then
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] nft delete table ip %s\n' "$NFT_TABLE"
            else
                nft delete table ip "$NFT_TABLE" 2>/dev/null \
                    && info "已清理 nft 后端留下的表 ip $NFT_TABLE"
            fi
        fi
        nft_clear_hooks
    fi
    if [ "$want" != firewalld ] && [ -s "$APPLIED_FILE" ] && firewalld_running; then
        fw_remove_file "$APPLIED_FILE" >/dev/null 2>&1 || true
    fi
    return 0
}

# 内核里可能存在"同端口、不同目标"的规则(手工加的、别的容器工具加的、旧版本没写注释留下的),
# 它们排在本工具的规则前面就会把流量抢走。这里只提示, 不自动删(可能是 Docker/K8s 的规则)。
detect_conflicts() {
    local bk p lp dest kind dip dp cp clp cdip cdp cm found=0
    invalidate_rules_cache
    while read -r bk p lp dest kind; do
        case "$dest" in
            *:*) dip="${dest%:*}"; dp="${dest##*:}" ;;
            *)   dip="$dest";      dp="" ;;
        esac
        if [ "$kind" = "redirect" ]; then dip="127.0.0.1"; fi
        [ -n "$dip" ] || dip="127.0.0.1"
        if [ -n "$dp" ]; then
            rule_in_conf "$p" "$lp" "$dip" "$dp" && continue
        else
            rule_in_conf "$p" "$lp" "$dip" "*" && continue
        fi
        while read -r cp clp cdip cdp cm; do
            [ "$cp" = "$p" ] && [ "$clp" = "$lp" ] || continue
            if [ "$cdip" != "$dip" ] || { [ -n "$dp" ] && [ "$cdp" != "$dp" ]; }; then
                found=1
                warn "内核里 ${p}/${lp} 还有一条指向 ${dip}:${dp:-?} 的规则(不是本工具写的), 可能先于本工具的规则生效"
            fi
        done < <(norm_rules)
    done < <(installed_rules_any)
    if [ "$found" = 1 ]; then
        info "用 '$PROG doctor' 看原始规则; 确认多余后按后端手工删除, 或重新用 '$PROG add ...' 覆盖同一入口端口。"
    fi
    return 0
}

do_apply() {
    need_root
    ensure_conf_dir
    resolve_backend || return 1
    legacy_migrate || true
    cleanup_other_backends "$BACKEND"
    ensure_ip_forward
    local n
    n=$(count_rules)
    info "后端: $BACKEND   规则: $n 条"
    local rc=0
    case "$BACKEND" in
        iptables)  ipt_apply  || rc=1 ;;
        nft)       nft_apply || rc=1 ;;
        firewalld) fw_apply  || rc=1 ;;
    esac
    if [ "$rc" -eq 0 ]; then
        save_applied
        state_set backend "$BACKEND"
        ok "规则已生效$( [ "$n" -eq 0 ] && printf '(当前没有规则, 已清空)' )"
        if [ "$DRY_RUN" != 1 ] && [ "$n" -gt 0 ]; then
            detect_conflicts
        fi
    else
        err "规则应用失败"
    fi
    invalidate_rules_cache
    return "$rc"
}

# 只清理防火墙里的转发规则, 不动规则配置文件(卸载时用)
# 没有可用后端时置 CLEAR_SKIPPED=1, 由调用方决定如何提示
CLEAR_SKIPPED=0
clear_firewall_rules() {
    local b rc=0
    CLEAR_SKIPPED=0
    b=$(current_backend)
    case "$b" in
        iptables)  ipt_clear  || rc=1 ;;
        nft)       nft_clear  || rc=1 ;;
        firewalld) fw_clear   || rc=1 ;;
        *) warn "未探测到可用后端, 跳过清理内核规则"; CLEAR_SKIPPED=1; return 0 ;;
    esac
    if [ "$DRY_RUN" != 1 ] && [ "$rc" = 0 ]; then
        ensure_conf_dir
        : > "$APPLIED_FILE"
    fi
    invalidate_rules_cache
    return "$rc"
}

# 清空转发规则
#   默认只清"本工具下发/配置里有的", 别人的规则一条不动;
#   --all 时连内核里扫描到的其它来源的 DNAT/REDIRECT 一起删(需要再确认一次)。
do_clear() {
    need_root
    ensure_conf_dir
    invalidate_rules_cache
    local loc own_n ext_n ext_list choice
    loc=$(installed_located)
    own_n=$(printf '%s\n' "$loc" | awk -F'|' 'NF >= 7 && $6 == 1' | grep -c . || true)
    ext_list=$(printf '%s\n' "$loc" | awk -F'|' 'NF >= 7 && $6 == 0')
    ext_n=$(printf '%s\n' "$ext_list" | grep -c . || true)

    if [ "$RAW" != 1 ] && [ "${own_n:-0}" -gt 0 -o "${ext_n:-0}" -gt 0 ]; then
        printf '\n  扫描到的转发规则:\n'
        printf '    本工具写入/在配置中: %s 条\n' "${own_n:-0}"
        printf '    其它来源(手工/别的工具): %s 条\n' "${ext_n:-0}"
        if [ "${ext_n:-0}" -gt 0 ]; then
            printf '%s' "$ext_list" | awk -F'|' '{ printf "      %-8s %-5s %-6s -> %-20s %s\n", $1, $2, $3, $4, $5 }'
        fi
        printf '\n'
    fi

    if [ "$ASSUME_YES" = 1 ]; then
        choice=1
        [ "$OPT_ALL" = 1 ] && choice=2
    else
        printf '  清空方式:\n'
        printf '    1) 只清本工具的规则(保留其它来源)   [默认]\n'
        printf '    2) 连其它来源的规则一起清(会删别人的 DNAT/REDIRECT)\n'
        printf '    3) 取消\n'
        read -r -p '  请选择 [1-3]: ' choice || choice=3
    fi

    case "${choice:-3}" in
        1) ;;
        2)  if [ "$ASSUME_YES" != 1 ]; then
                if [ "${ext_n:-0}" -eq 0 ]; then
                    info "没有发现其它来源的规则, 按方式 1 处理"
                else
                    confirm "确认连 ${ext_n} 条外部规则一起删除? 这会改动不是本工具写的防火墙规则 [y/N] " \
                        || { info "已取消"; return 0; }
                fi
            fi
            ;;
        *) info "已取消"; return 0 ;;
    esac

    clear_own_rules || true

    if [ "${choice:-3}" = 2 ] && [ "${ext_n:-0}" -gt 0 ]; then
        clear_external_rules || true
        if firewalld_running; then firewall-cmd --reload >/dev/null 2>&1 || true; fi
    fi

    backup_rules
    if [ "$DRY_RUN" != 1 ]; then
        ensure_conf_dir
        : > "$RULES_FILE"
        : > "$APPLIED_FILE"
    fi
    ok "已清空转发规则"
    invalidate_rules_cache
    return 0
}

# 清掉本工具在所有后端留下的规则(不看当前后端, 因为可能来回切过)
clear_own_rules() {
    local rc=0
    if ipt_usable; then ipt_clear || rc=1; fi
    if cmd_exists nft; then
        nft_clear >/dev/null 2>&1 || true
        nft_clear_hooks >/dev/null 2>&1 || true
    fi
    if firewalld_running; then fw_clear || rc=1; fi
    return "$rc"
}

# 删掉扫描到的"非本工具"规则(--all 时用)
clear_external_rules() {
    local bk p lp dest kind own loc n=0 rc=0
    while IFS='|' read -r bk p lp dest kind own loc; do
        [ -z "${bk:-}" ] && continue
        [ "$own" = 1 ] && continue
        if [ "$DRY_RUN" = 1 ]; then
            printf '  [dry-run] 删除外部规则: %s %s -> %s (%s, %s)\n' "$p" "$lp" "$dest" "$kind" "$bk"
            continue
        fi
        if delete_located "$bk" "$p" "$lp" "$dest" "$kind" "$loc"; then
            info "已删除外部规则: $p $lp -> $dest ($bk)"
            n=$((n + 1))
        else
            warn "删除失败: $p $lp -> $dest ($bk)"
            rc=1
        fi
    done < <(installed_located | awk -F'|' 'NF >= 7 && $6 == 0')
    [ "$n" -eq 0 ] && [ "$DRY_RUN" != 1 ] && info "没有删除任何外部规则"
    return "$rc"
}

#-------------------------------------------------------------------------------
# 读取"内核/防火墙里实际存在"的转发规则
#   统一输出: <proto> <lport> <dest> <kind>
#     kind=dnat     dest 形如 10.0.0.5:80 (也可能是裸 IP, 表示端口不变)
#     kind=redirect dest 形如 :80
# 查看/测试都以真实规则为准, 不依赖本工具写下的注释标记,
# 因此手工加的规则、别的工具加的规则、旧版本残留的规则都能被识别出来。
#-------------------------------------------------------------------------------
fw_zone() {
    local z="${OPT_ZONE:-${FORWARD_ZONE:-}}"
    [ -z "$z" ] && z=$(firewall-cmd --get-default-zone 2>/dev/null)
    [ -z "$z" ] && z=public
    printf '%s' "$z"
}

is_local_ip() {   # $1 = IPv4
    local x
    for x in $(local_ips); do
        [ "$x" = "$1" ] && return 0
    done
    return 1
}

installed_rules_ipt() {
    iptq -t nat -S 2>/dev/null | awk '
        {
            proto = ""; lport = ""; kind = ""; dest = "";
            for (i = 1; i <= NF; i++) {
                if ($i == "-p" || $i == "--protocol")                proto = $(i+1);
                else if ($i == "--dport" || $i == "--destination-port") lport = $(i+1);
                else if ($i == "-j" || $i == "--jump")               kind  = $(i+1);
                else if ($i == "--to-destination")                   dest  = $(i+1);
                else if ($i == "--to-ports")                         dest  = ":" $(i+1);
            }
            if (proto == "" || lport == "" || kind == "" || dest == "") next;
            if (lport ~ /^[{}]/) next;      # 端口集合暂不展开
            if (kind == "DNAT")          print proto, lport, dest, "dnat";
            else if (kind == "REDIRECT") print proto, lport, dest, "redirect";
        }'
}

# 扫整份 ruleset(而不只是自己的表), 这样别的表/别的工具/旧版本留下的规则也能显示出来
installed_rules_nft() {
    nft list ruleset 2>/dev/null | awk '
        {
            for (i = 2; i <= NF; i++) {
                if ($i != "dport") continue;
                proto = $(i-1); lport = $(i+1);
                if (proto !~ /^(tcp|udp|sctp|dccp)$/) continue;
                if (lport ~ /^[{}]/) continue;
                for (j = i + 2; j <= NF; j++) {
                    if ($j == "dnat" && $(j+1) == "to" && $(j+2) != "")     { print proto, lport, $(j+2), "dnat";     break }
                    if ($j == "redirect" && $(j+1) == "to" && $(j+2) != "") { print proto, lport, $(j+2), "redirect"; break }
                }
            }
        }'
}

installed_rules_fw() {
    local zone line lp proto tp ta rest
    zone=$(fw_zone)
    firewall-cmd --zone="$zone" --list-forward-ports 2>/dev/null | while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in port=*) ;; *) continue ;; esac
        line="${line#port=}"
        case "$line" in *:proto=*) ;; *) continue ;; esac
        lp="${line%%:proto=*}"
        rest="${line#*:proto=}"
        proto="${rest%%:*}"
        case "$rest" in *:toport=*) ;; *) continue ;; esac
        rest="${rest#*:toport=}"
        tp="${rest%%:*}"
        ta=""
        case "$rest" in *:toaddr=*) ta="${rest#*:toaddr=}";; esac
        if [ -n "$ta" ]; then
            printf '%s %s %s:%s dnat\n' "$proto" "$lp" "$ta" "$tp"
        else
            printf '%s %s :%s redirect\n' "$proto" "$lp" "$tp"
        fi
    done
}

installed_rules() {
    local b
    b=$(current_backend)
    case "$b" in
        iptables)  installed_rules_ipt ;;
        nft)       installed_rules_nft ;;
        firewalld) installed_rules_fw ;;
        *)         return 0 ;;
    esac
}

#-------------------------------------------------------------------------------
# 可定位(可删除)的规则枚举
#   输出: <backend>|<proto>|<lport>|<dest>|<kind>|<own>|<locator>
#     own=1 : 带本工具标记(iptables 注释 / nft 自己的表)或本工具配置里就有
#     locator:
#       iptables  -> nat|CHAIN     (删除时按 proto/lport/kind/dest 在该链里找)
#       nft       -> fam|table|chain|handle
#       firewalld -> port=..:proto=..:toport=..[:toaddr=..]
#   为了能"清空/测试"别人写的规则, 这里刻意不区分来源, 一律枚举出来。
#-------------------------------------------------------------------------------

# 按 shell 引号规则切词: iptables -S 的输出里注释是带引号的, 直接 $* 拆会被空格拆散
# (以前就踩过: --comment "portfwd: old" -> 参数变成两个, 报 Bad argument `old')
split_argv() {
    SPLIT_ARGV=()
    local s="$1" n=${#1} i c tok="" inq=""
    for ((i = 0; i < n; i++)); do
        c=${s:i:1}
        if [ -z "$inq" ]; then
            case "$c" in
                ' '|$'\t')
                    if [ -n "$tok" ]; then SPLIT_ARGV+=("$tok"); tok=""; fi
                    ;;
                '"'|"'") inq="$c" ;;
                *) tok="$tok$c" ;;
            esac
        else
            if [ "$c" = "$inq" ]; then inq=""; else tok="$tok$c"; fi
        fi
    done
    [ -n "$tok" ] && SPLIT_ARGV+=("$tok")
    return 0
}

located_ipt() {
    local ch line p lp kind dest own i
    for ch in PREROUTING OUTPUT POSTROUTING; do
        while IFS= read -r line; do
            case "$line" in "-A $ch "*) ;; *) continue ;; esac
            case "$line" in *DNAT*|*REDIRECT*) ;; *) continue ;; esac
            split_argv "$line"
            p=""; lp=""; kind=""; dest=""
            for ((i = 0; i < ${#SPLIT_ARGV[@]}; i++)); do
                case "${SPLIT_ARGV[i]}" in
                    -p|--protocol)              p="${SPLIT_ARGV[i+1]:-}" ;;
                    --dport|--destination-port) lp="${SPLIT_ARGV[i+1]:-}" ;;
                    -j|--jump)                  kind="${SPLIT_ARGV[i+1]:-}" ;;
                    --to-destination)           dest="${SPLIT_ARGV[i+1]:-}" ;;
                    --to-ports)                 dest=":${SPLIT_ARGV[i+1]:-}" ;;
                esac
            done
            [ -n "$p" ] && [ -n "$lp" ] && [ -n "$kind" ] && [ -n "$dest" ] || continue
            case "$lp" in ''|*[!0-9]*) continue ;; esac
            own=0
            case "$line" in *"${IPT_TAG}:"*) own=1 ;; esac
            case "$kind" in
                DNAT)     printf 'iptables|%s|%s|%s|dnat|%s|nat|%s\n' "$p" "$lp" "$dest" "$own" "$ch" ;;
                REDIRECT) printf 'iptables|%s|%s|%s|redirect|%s|nat|%s\n' "$p" "$lp" "$dest" "$own" "$ch" ;;
            esac
        done < <(iptq -t nat -S "$ch" 2>/dev/null)
    done
}

located_nft() {
    nft -a list ruleset 2>/dev/null | awk -v own_tbl="$NFT_TABLE" '
        /^table / {
            fam = $2; tbl = $3
            sub(/[[:space:]]*\{.*$/, "", tbl)
            chain = ""
            next
        }
        /^[[:space:]]+chain / {
            chain = $2
            sub(/[[:space:]]*\{.*$/, "", chain)
            next
        }
        {
            if (fam == "" || tbl == "" || chain == "") next
            h = ""
            if (NF >= 3 && $(NF-2) == "#" && $(NF-1) == "handle" && $NF ~ /^[0-9]+$/) h = $NF
            kind = ""; dest = ""
            for (i = 2; i <= NF; i++) {
                if ($i != "dport") continue
                proto = $(i-1); lport = $(i+1)
                if (proto !~ /^(tcp|udp|sctp|dccp)$/) continue
                if (lport !~ /^[0-9]+$/) continue
                for (j = i + 2; j <= NF; j++) {
                    if ($j == "dnat" && $(j+1) == "to" && $(j+2) != "")     { dest = $(j+2); kind = "dnat";     break }
                    if ($j == "redirect" && $(j+1) == "to" && $(j+2) != "") { dest = $(j+2); kind = "redirect"; break }
                }
                if (kind != "") break
            }
            if (kind == "") next
            own = 0
            if (tbl == own_tbl) own = 1
            else if (index($0, "comment \"forward\"") > 0) own = 1
            printf "nft|%s|%s|%s|%s|%d|%s|%s|%s|%s\n", proto, lport, dest, kind, own, fam, tbl, chain, h
            next
        }
    '
}

located_fw() {
    local zone line rest lp proto tp ta dest kind own
    zone=$(fw_zone)
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        case "$line" in port=*) ;; *) continue ;; esac
        rest="${line#port=}"
        case "$rest" in *:proto=*) ;; *) continue ;; esac
        lp="${rest%%:proto=*}"
        rest="${rest#*:proto=}"
        proto="${rest%%:*}"
        case "$rest" in *:toport=*) ;; *) continue ;; esac
        rest="${rest#*:toport=}"
        tp="${rest%%:*}"
        ta=""
        case "$rest" in *:toaddr=*) ta="${rest#*:toaddr=}" ;; esac
        if [ -n "$ta" ]; then
            dest="$ta:$tp"; kind="dnat"
        else
            dest=":$tp";    kind="redirect"
        fi
        case "$lp" in ''|*[!0-9]*) continue ;; esac
        case "$tp" in ''|*[!0-9]*) continue ;; esac
        own=0
        if [ "$kind" = dnat ]; then
            rule_in_conf "$proto" "$lp" "$ta" "$tp" && own=1
        else
            rule_in_conf "$proto" "$lp" "127.0.0.1" "$tp" && own=1
        fi
        printf 'firewalld|%s|%s|%s|%s|%d|%s\n' "$proto" "$lp" "$dest" "$kind" "$own" "$line"
    done < <(firewall-cmd --zone="$zone" --list-forward-ports 2>/dev/null)
}

LOCATED_CACHE=""
LOCATED_DONE=0
invalidate_rules_cache() {
    RULES_ANY_CACHE=""; RULES_ANY_DONE=0
    LOCATED_CACHE="";   LOCATED_DONE=0
}

installed_located() {
    if [ "$LOCATED_DONE" = 1 ]; then
        [ -n "$LOCATED_CACHE" ] && printf '%s\n' "$LOCATED_CACHE"
        return 0
    fi
    LOCATED_CACHE=$(
        {
            if ipt_usable; then located_ipt; fi
            if cmd_exists nft; then located_nft; fi
            if firewalld_running; then located_fw; fi
        } | awk -F'|' 'NF >= 7'
    )
    LOCATED_DONE=1
    [ -n "$LOCATED_CACHE" ] && printf '%s\n' "$LOCATED_CACHE"
    return 0
}

# 扫描所有可用后端, 输出 <backend> <proto> <lport> <dest> <kind>
# 目的: 规则可能不是当前后端写的(切过后端 / 别的工具写的 / 旧版本留下的),
#       只看当前后端就会"明明有规则却识别不到"。
RULES_ANY_CACHE=""
RULES_ANY_DONE=0
installed_rules_any() {
    installed_located | awk -F'|' '
        NF >= 7 && !seen[$2" "$3" "$4" "$5]++ { printf "%s %s %s %s %s\n", $1, $2, $3, $4, $5 }'
}

# 删掉一条枚举出来的规则(own=0 的也能删, 供"连别人的规则一起清"用)
delete_located() {   # backend proto lport dest kind locator
    local bk="$1" p="$2" lp="$3" dest="$4" kind="$5" loc="$6"
    local tbl ch line n=0 guard=0 fam h
    case "$bk" in
        iptables)
            tbl="${loc%%|*}"; ch="${loc##*|}"
            while [ "$guard" -lt 500 ]; do
                guard=$((guard + 1))
                line=$(ipt_find_rule "$tbl" "$ch" "$p" "$lp" "$kind" "$dest")
                [ -z "$line" ] && break
                split_argv "$line"
                iptm -t "$tbl" -D "$ch" "${SPLIT_ARGV[@]:2}" || break
                n=$((n + 1))
            done
            [ "$n" -gt 0 ] && return 0
            return 1
            ;;
        nft)
            fam="${loc%%|*}"; loc="${loc#*|}"
            tbl="${loc%%|*}"; loc="${loc#*|}"
            ch="${loc%%|*}";  h="${loc##*|}"
            [ -n "$fam" ] && [ -n "$tbl" ] && [ -n "$ch" ] && [ -n "$h" ] || return 1
            nftm delete rule "$fam" "$tbl" "$ch" handle "$h" 2>/dev/null || return 1
            return 0
            ;;
        firewalld)
            fw_perm --permanent --remove-forward-port="$loc" || return 1
            return 0
            ;;
    esac
    return 1
}

# 在 iptables 某条链里按条件找第一条匹配的 -A 行(用于精确删除)
ipt_find_rule() {   # table chain proto lport kind dest
    local tbl="$1" ch="$2" p="$3" lp="$4" kind="$5" dest="$6"
    iptq -t "$tbl" -S "$ch" 2>/dev/null | awk -v ch="$ch" -v p="$p" -v lp="$lp" -v k="$kind" -v d="$dest" '
        $1 != "-A" || $2 != ch { next }
        {
            mp = ""; ml = ""; mk = ""; md = "";
            for (i = 3; i <= NF; i++) {
                if ($i == "-p" || $i == "--protocol")   mp = $(i+1);
                else if ($i == "--dport" || $i == "--destination-port") ml = $(i+1);
                else if ($i == "-j" || $i == "--jump")  mk = $(i+1);
                else if ($i == "--to-destination")      md = $(i+1);
                else if ($i == "--to-ports")            md = ":" $(i+1);
            }
            if (mp != p || ml != lp || md != d) next;
            if (k == "dnat" && mk != "DNAT") next;
            if (k == "redirect" && mk != "REDIRECT") next;
            print; exit
        }'
}

# 配置里是否有这条(供"仅内核"标记使用); $4 可以是 * 表示任意目标端口
rule_in_conf() {   # proto lport dip dport
    local p lp dip dp m
    while read -r p lp dip dp m; do
        [ "$p" = "$1" ] && [ "$lp" = "$2" ] && [ "$dip" = "$3" ] || continue
        { [ "$4" = "*" ] || [ "$4" = "$dp" ]; } && return 0
    done < <(norm_rules)
    return 1
}

check_rule_installed() {   # proto lport dip dport
    local wp="$1" wl="$2" wdip="$3" wdp="$4" bk p lp dest kind dip dp
    while read -r bk p lp dest kind; do
        [ "$p" = "$wp" ] && [ "$lp" = "$wl" ] || continue
        case "$dest" in
            *:*) dip="${dest%:*}"; dp="${dest##*:}" ;;
            *)   dip="$dest";      dp="$wl" ;;
        esac
        [ -z "$dip" ] && dip="127.0.0.1"
        [ "$dp" = "$wdp" ] || continue
        case "$kind" in
            dnat)
                [ "$dip" = "$wdip" ] && return 0
                # 目标写成本机网卡地址的 DNAT, 与 REDIRECT 等效
                if { [ "$wdip" = "127.0.0.1" ] || [ "$wdip" = "0.0.0.0" ]; } && is_local_ip "$dip"; then
                    return 0
                fi
                ;;
            redirect)
                if [ "$wdip" = "127.0.0.1" ] || [ "$wdip" = "0.0.0.0" ]; then
                    return 0
                fi
                ;;
        esac
    done < <(installed_rules_any)
    return 1
}

do_list() {
    local p lp dip dp m mode state n=0 b total=0 extra=0
    invalidate_rules_cache
    if [ "$(id -u 2>/dev/null || echo 0)" != 0 ]; then
        warn "当前不是 root, 可能读不到内核里的防火墙规则; 请用 sudo 运行"
    fi
    b=$(current_backend)
    if [ "$RAW" = 1 ]; then
        while read -r p lp dip dp m; do
            printf '%s %s %s %s %s\n' "$p" "$lp" "$dip" "$dp" "$m"
        done < <(norm_rules)
        return 0
    fi

    if [ "$(count_rules)" -eq 0 ]; then
        info "配置文件里没有转发规则 ($RULES_FILE)"
    else
        printf '%-6s %-7s %-17s %-7s %-6s %s\n' "PROTO" "LPORT" "DEST_IP" "DPORT" "SNAT" "STATE"
        while read -r p lp dip dp m; do
            n=$((n + 1))
            mode=$(rule_mode "$dip")
            if check_rule_installed "$p" "$lp" "$dip" "$dp"; then
                state="${C_GRN}已生效${C_RST}"
            else
                state="${C_YEL}未生效${C_RST}"
            fi
            printf '%-6s %-7s %-17s %-7s %-6s %b' "$p" "$lp" "$dip" "$dp" \
                "$([ "$m" = 1 ] && echo yes || echo no)" "$state"
            [ "$mode" = local ] && printf ' (本机)'
            printf '\n'
        done < <(norm_rules)
        printf '%s共 %d 条配置规则, 后端: %s%s\n' "$C_DIM" "$n" "${b:-未探测到}" "$C_RST"
    fi

    printf '\n%s内核里实际生效的转发规则:%s\n' "$C_DIM" "$C_RST"
    while read -r bk p lp dest kind; do
        total=$((total + 1))
        case "$dest" in
            *:*) dip="${dest%:*}"; dp="${dest##*:}" ;;
            *)   dip="$dest";      dp="*" ;;
        esac
        [ -z "$dip" ] && dip="127.0.0.1"
        if rule_in_conf "$p" "$lp" "$dip" "$dp"; then
            state="${C_GRN}在配置中${C_RST}"
        else
            state="${C_YEL}不在配置中${C_RST}"
            extra=$((extra + 1))
        fi
        [ "$bk" != "${b:-}" ] && state="$state ${C_DIM}($bk 写入)${C_RST}"
        printf '  %-4s %-6s -> %-17s %-6s %-8s %b\n' "$p" "$lp" "$dip" "$dp" "$kind" "$state"
    done < <(installed_rules_any)

    if [ "$total" -eq 0 ]; then
        info "  (没有读到任何生效规则)"
        if [ -z "$b" ]; then
            warn "  没有可用的转发后端, 请先看: $PROG status"
        else
            warn "  当前后端是 $b, 若你确信规则已存在, 请执行: $PROG doctor"
        fi
    elif [ "$extra" -gt 0 ]; then
        info "  其中 $extra 条不在配置文件里(手工或其它工具所加)。"
        info "  想让本工具接管开机自动恢复, 请重新用 '$PROG add ...' 添加一次。"
    fi
}

# 把内核里已经生效、但配置文件里没有的规则"收编"进 rules.conf,
# 这样它们才会被开机自启统一恢复。
do_import() {
    need_root
    ensure_conf_dir
    invalidate_rules_cache
    local bk p lp dest kind dip dp masq n=0
    while read -r bk p lp dest kind; do
        case "$dest" in
            *:*) dip="${dest%:*}"; dp="${dest##*:}" ;;
            *)   dip="$dest";      dp="$lp" ;;
        esac
        if [ "$kind" = "redirect" ] || [ "$dip" = "0.0.0.0" ]; then dip="127.0.0.1"; fi
        [ -n "$dip" ] || dip="127.0.0.1"
        if ! valid_ipv4 "$dip" || ! valid_port "$dp"; then
            warn "跳过无法解析的规则: $p $lp -> $dest ($kind)"
            continue
        fi
        rule_in_conf "$p" "$lp" "$dip" "$dp" && continue
        masq=0
        if [ "$dip" != "127.0.0.1" ] && ! is_local_ip "$dip"; then masq=1; fi
        rule_add "$p" "$lp" "$dip" "$dp" "$masq"
        info "收编: $p $lp -> $dip:$dp"
        n=$((n + 1))
    done < <(installed_rules_any)

    if [ "$n" -eq 0 ]; then
        info "没有需要收编的规则(内核里的规则都已在 $RULES_FILE 中)"
        return 0
    fi
    info "已收编 $n 条规则到 $RULES_FILE"
    info "执行 '$PROG apply' 后由本工具统一管理, 开机自动恢复。"
}

# TCP 端口连通性探测 (UDP 返回 2 表示无法可靠探测)
port_open() {    local h="$1" pt="$2" pr="${3:-tcp}" have_nc_z=0
    if [ "$pr" != tcp ]; then
        return 2
    fi
    # busybox nc 不一定支持 -z, 先探测能力, 再决定用 nc 还是 bash 的 /dev/tcp
    if cmd_exists nc && nc -h 2>&1 | grep -q -- '-z'; then
        have_nc_z=1
    fi
    if [ "$have_nc_z" = 1 ]; then
        if cmd_exists timeout; then
            timeout 3 nc -z "$h" "$pt" >/dev/null 2>&1
        else
            nc -z -w 3 "$h" "$pt" >/dev/null 2>&1
        fi
        return $?
    fi
    if cmd_exists timeout; then
        timeout 3 bash -c "exec 3<>/dev/tcp/${h}/${pt}" >/dev/null 2>&1
        return $?
    fi
    ( exec 3<>/dev/tcp/"${h}"/"${pt}" ) >/dev/null 2>&1
    return $?
}

do_test() {
    local only="${1:-}" p lp dip dp m mode tgt tport found=0 fail=0 nconf=0
    need_root
    invalidate_rules_cache
    resolve_backend >/dev/null 2>&1 || true

    nconf=$(count_rules)
    if [ "$nconf" -eq 0 ]; then
        info "配置文件里没有规则, 只测试内核里扫描到的规则"
    fi

    # 1) 配置里的规则
    while read -r p lp dip dp m; do
        if [ -n "$only" ] && [ "$only" != "$lp" ]; then
            continue
        fi
        found=1
        mode=$(rule_mode "$dip")
        log "----------------------------------------------"
        log "规则: ${p} ${lp} -> ${dip}:${dp}  (${mode}, 来自配置)"
        if check_rule_installed "$p" "$lp" "$dip" "$dp"; then
            ok "防火墙规则已安装"
        else
            warn "防火墙规则未安装, 请先执行: $PROG apply"
            fail=1
        fi
        if [ "$mode" = local ]; then
            tgt="127.0.0.1"; tport="$dp"
        else
            tgt="$dip"; tport="$dp"
        fi
        port_open "$tgt" "$tport" "$p"
        case $? in
            0) ok "目标 ${tgt}:${tport}/${p} 可连接" ;;
            2) info "UDP 无法可靠探测, 请用实际业务验证" ;;
            *) warn "目标 ${tgt}:${tport}/${p} 连接失败(服务未启动或被防火墙拦截)"; fail=1 ;;
        esac
    done < <(norm_rules)

    # 2) 内核里有、但配置里没有的规则(手工加的 / 别的工具加的 / 旧版本残留)
    local bk dest kind own loc kdip kdp
    while IFS='|' read -r bk p lp dest kind own loc; do
        [ -z "${bk:-}" ] && continue
        case "$dest" in
            *:*) kdip="${dest%:*}"; kdp="${dest##*:}" ;;
            *)   kdip="$dest";      kdp="$lp" ;;
        esac
        [ -z "$kdip" ] && kdip="127.0.0.1"
        [ "$kind" = redirect ] && kdip="127.0.0.1"
        rule_in_conf "$p" "$lp" "$kdip" "$kdp" && continue
        if [ -n "$only" ] && [ "$only" != "$lp" ]; then
            continue
        fi
        found=1
        log "----------------------------------------------"
        if [ "$own" = 1 ]; then
            log "规则: ${p} ${lp} -> ${kdip}:${kdp}  (来自 $bk, 不在配置文件中)"
        else
            log "规则: ${p} ${lp} -> ${kdip}:${kdp}  (来自 $bk, 不是本工具写入的)"
        fi
        ok "防火墙里确实有这条规则"
        if [ "$kind" = redirect ] || [ "$kdip" = "127.0.0.1" ]; then
            tgt="127.0.0.1"; tport="$kdp"
        else
            tgt="$kdip"; tport="$kdp"
        fi
        port_open "$tgt" "$tport" "$p"
        case $? in
            0) ok "目标 ${tgt}:${tport}/${p} 可连接" ;;
            2) info "UDP 无法可靠探测, 请用实际业务验证" ;;
            *) warn "目标 ${tgt}:${tport}/${p} 连接失败(服务未启动或被防火墙拦截)"; fail=1 ;;
        esac
    done < <(installed_located)

    [ "$found" = 0 ] && { warn "没有找到监听端口为 ${only} 的规则(配置和内核里都没有)"; fail=1; }
    log "----------------------------------------------"
    info "提示: 在转发主机上用 127.0.0.1:${only:-<入口端口>} 测试不会经过 PREROUTING,"
    info "      DNAT 必须从其它机器发起才有效(本机测试请用目标端口)."
    [ "$fail" = 0 ] && ok "测试通过" || warn "存在问题, 见上面的提示"
    return "$fail"
}

do_status() {
    local b avail_ipt avail_nft avail_fw ipfwd n persist z init
    invalidate_rules_cache
    init=$(init_system)
    b=$(current_backend)
    avail_ipt="否"; ipt_usable && avail_ipt="是"
    avail_nft="否"; nft_usable && avail_nft="是"
    avail_fw="否";  firewalld_running && avail_fw="是"
    ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null | tr -d ' ')
    [ -z "$ipfwd" ] && ipfwd="未知"
    n=$(count_rules)

    if [ "$RAW" = 1 ]; then
        printf 'version=%s\n' "$VERSION"
        printf 'distro=%s\n' "$(distro_name)"
        printf 'kernel=%s\n' "$(uname -r 2>/dev/null)"
        printf 'init=%s\n' "$init"
        printf 'backend=%s\n' "${b:-none}"
        printf 'iptables=%s\n' "$avail_ipt"
        printf 'nft=%s\n' "$avail_nft"
        printf 'firewalld=%s\n' "$avail_fw"
        printf 'ip_forward=%s\n' "$ipfwd"
        printf 'rules=%s\n' "$n"
        printf 'rules_file=%s\n' "$RULES_FILE"
        printf 'persist=%s\n' "$(persist_enabled && printf yes || printf no)"
        printf 'self_bin=%s\n' "$([ -e "$SELF_BIN" ] && printf installed || printf missing)"
        return 0
    fi

    log ""
    log "  ${C_BLU}${PROG} ${VERSION}${C_RST}"
    log "  发行版        : $(distro_name)"
    log "  内核          : $(uname -r 2>/dev/null || echo 未知)"
    log "  init 系统     : $init"
    log "  当前后端      : ${b:-未探测到}"
    log "  可用后端      : iptables=${avail_ipt}  nft=${avail_nft}  firewalld=${avail_fw}"
    if cmd_exists iptables; then
        case "$(iptables --version 2>/dev/null)" in
            *nf_tables*) log "  iptables 版本 : $(iptables --version 2>/dev/null) (工作在 nftables 之上)" ;;
            *)           log "  iptables 版本 : $(iptables --version 2>/dev/null)" ;;
        esac
    fi
    log "  ip_forward    : $ipfwd $([ "$ipfwd" = 1 ] && printf "(${C_GRN}已开启${C_RST})" || printf "(${C_YEL}未开启${C_RST})")"
    log "  规则数量      : $n"
    log "  开机自启      : $(persist_enabled && printf "已启用 (${init})" || printf "未启用")"
    if [ -e "$SELF_BIN" ]; then
        log "  程序本体      : $SELF_BIN (已安装)"
    else
        local pth
        pth=$(command -v forward 2>/dev/null || true)
        if [ -n "$pth" ] && [ "$pth" != "$SELF_BIN" ]; then
            log "  程序本体      : 未安装(当前 PATH 里是 $pth, 非本工具安装)"
        else
            log "  程序本体      : 未安装(仅能直接运行脚本文件)"
        fi
    fi
    log "  配置文件      : $RULES_FILE"
    log "  已应用快照    : $APPLIED_FILE"
    log "  sysctl 文件   : $SYSCTL_FILE"
    if [ "$avail_fw" = "是" ]; then
        log "  firewalld     : 运行中, 默认区域 $(firewall-cmd --get-default-zone 2>/dev/null)"
    fi
    if cmd_exists ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
        log "  ufw           : 已启用 (iptables 后端的 FORWARD 规则会插在链首, 通常无需额外操作)"
    fi
    if [ -d /var/lib/docker ]; then
        log "  docker        : 已安装 (本工具只操作自己的规则, 不会清空 Docker 的 NAT 表)"
    fi
    log ""
}

#-------------------------------------------------------------------------------
# 开机自启
#-------------------------------------------------------------------------------
self_path() {
    local p="$0"
    [ -h "$p" ] && p=$(readlink -f "$p" 2>/dev/null || printf '%s' "$0")
    printf '%s' "$p"
}

# 本工具的身份标识(写在文件头), 用来在 PATH 里认出自己的副本
TOOL_MARKER="__FORWARD_TOOL__"

# 判断某个文件是不是本工具的副本(含更早的、没有标识行的版本)
is_our_tool() {   # $1=路径
    [ -f "$1" ] || return 1
    grep -q -- "$TOOL_MARKER" "$1" 2>/dev/null && return 0
    # 兼容更早的版本(没有标识行, 甚至还是 portfwd 时期的表名): 同时命中 3 个特征才认
    grep -qm1 '^readonly PROG="forward"' "$1" 2>/dev/null || return 1
    grep -qm1 'RULES_FILE="$CONF_DIR/rules.conf"' "$1" 2>/dev/null || return 1
    grep -qm1 '^readonly NFT_TABLE=' "$1" 2>/dev/null || return 1
    return 0
}

# 列出 PATH 中所有本工具的副本(含 /usr/local/sbin 等标准目录)
# 只认本工具的文件, 不会误删别的同名程序
tool_copies() {   # 输出: 每行一个绝对路径
    local d f seen="|"
    for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin \
             $(printf '%s' "${PATH:-}" | tr ':' ' '); do
        [ -n "$d" ] || continue
        f="$d/forward"
        case "$seen" in *"|$f|"*) continue ;; esac
        seen="$seen$f|"
        is_our_tool "$f" && printf '%s\n' "$f"
    done
    return 0
}

# 读取某个副本里声明的版本号
tool_version_of() {   # $1=路径
    sed -n 's/^readonly VERSION="\(.*\)"$/\1/p' "$1" 2>/dev/null | head -n 1
}

persist_enabled() {
    local init
    init=$(init_system)
    case "$init" in
        systemd)
            [ -f "$SYSTEMD_UNIT" ] || return 1
            systemctl is-enabled forward.service >/dev/null 2>&1
            ;;
        openrc)
            [ -x "$INIT_SCRIPT" ] || return 1
            rc-update show default 2>/dev/null | grep -q forward
            ;;
        sysvinit)
            local rl
            for rl in /etc/rc2.d/S??forward /etc/rc3.d/S??forward /etc/rc.d/rc3.d/S??forward; do
                [ -e "$rl" ] && return 0
            done
            return 1
            ;;
        *)
            return 1
            ;;
    esac
}

write_systemd_unit() {
    mkdir -p "$(dirname "$SYSTEMD_UNIT")" 2>/dev/null || return 1
    cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=forward 端口转发规则恢复
After=network-online.target nftables.service iptables.service netfilter-persistent.service firewalld.service docker.service
Wants=network-online.target
ConditionPathExists=$RULES_FILE

[Service]
Type=oneshot
RemainAfterExit=yes
StandardOutput=null
ExecStart=$SELF_BIN apply --quiet

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SYSTEMD_UNIT" 2>/dev/null || true
}

write_openrc_script() {
    cat > "$INIT_SCRIPT" <<EOF
#!/sbin/openrc-run
# 由 forward 生成
description="forward 端口转发规则恢复"

depend() {
    need localmount
    use net
    after nftables iptables firewall
}

start() {
    ebegin "应用 forward 转发规则"
    $SELF_BIN apply --quiet
    eend \$?
}

stop() {
    ebegin "forward 规则由防火墙自身管理, 停止时不做清理"
    eend 0
}
EOF
    chmod 755 "$INIT_SCRIPT" 2>/dev/null || true
}

write_sysv_script() {
    cat > "$INIT_SCRIPT" <<EOF
#!/bin/sh
# chkconfig: 2345 90 10
# description: 按 $RULES_FILE 恢复端口转发规则(forward)
### BEGIN INIT INFO
# Provides:          forward
# Required-Start:    \$local_fs \$network
# Required-Stop:     \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: forward 端口转发规则恢复
# Description:       启动时按 $RULES_FILE 恢复端口转发规则
### END INIT INFO
case "\$1" in
    start) $SELF_BIN apply --quiet ;;
    stop)  : ;;
    restart|force-reload) $SELF_BIN apply --quiet ;;
    status) $SELF_BIN status ;;
    *) exit 1 ;;
esac
exit 0
EOF
    chmod 755 "$INIT_SCRIPT" 2>/dev/null || true
}

persist_install() {
    need_root
    ensure_conf_dir
    legacy_migrate || true
    local src init
    src=$(self_path)
    if [ ! -f "$src" ] || [ ! -r "$src" ]; then
        err "无法定位脚本本体($src); 请先把脚本保存成文件再执行 install"
        err "  例如: curl -o forward.sh <地址> && sudo bash forward.sh install"
        return 1
    fi
    # 1) 安装自身到固定路径(服务要用)
    if [ "$DRY_RUN" = 1 ]; then
        printf '  [dry-run] install -m 0755 %s %s\n' "$src" "$SELF_BIN"
    else
        mkdir -p "$(dirname "$SELF_BIN")" 2>/dev/null || true
        if [ "$src" != "$SELF_BIN" ]; then
            # 已有同名文件但不是本脚本时先备份, 避免覆盖别人放进去的脚本
            if [ -f "$SELF_BIN" ] && ! cmp -s "$src" "$SELF_BIN" 2>/dev/null; then
                if cp -f "$SELF_BIN" "$SELF_BIN.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null; then
                    info "已备份原有 $SELF_BIN"
                fi
            fi
            if ! { install -m 0755 "$src" "$SELF_BIN" 2>/dev/null \
                   || cp -f "$src" "$SELF_BIN" 2>/dev/null; }; then
                err "无法安装到 $SELF_BIN (可能是只读文件系统)"
                return 1
            fi
            chmod 755 "$SELF_BIN" 2>/dev/null || true
        fi
    fi
    # 2) ip_forward 持久化
    [ "$DRY_RUN" = 1 ] || persist_ip_forward
    # 2.5) 清掉 PATH 里其它位置的本工具副本, 否则 'forward' 可能仍指向旧版本
    if [ "$DRY_RUN" != 1 ]; then
        local dup
        while IFS= read -r dup; do
            [ -n "$dup" ] || continue
            [ "$dup" = "$SELF_BIN" ] && continue
            if rm -f -- "$dup" 2>/dev/null; then
                info "已移除重复副本 $dup (避免它抢先于 $SELF_BIN)"
            fi
        done <<EOF2
$(tool_copies)
EOF2
        hash -r 2>/dev/null || true
    fi
    # 3) 自启
    init=$(init_system)
    case "$init" in
        systemd)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] 写入 %s\n' "$SYSTEMD_UNIT"
                printf '  [dry-run] systemctl daemon-reload; systemctl enable --now forward.service\n'
            else
                write_systemd_unit || { err "写入 $SYSTEMD_UNIT 失败"; return 1; }
                systemctl daemon-reload >/dev/null 2>&1 || true
                systemctl enable forward.service >/dev/null 2>&1 \
                    || warn "systemctl enable 失败(容器环境可忽略)"
                systemctl restart forward.service >/dev/null 2>&1 \
                    || warn "systemctl start 失败, 用 journalctl -u forward 查看原因"
            fi
            ;;
        openrc)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] 写入 %s; rc-update add forward default\n' "$INIT_SCRIPT"
            else
                write_openrc_script
                rc-update add forward default >/dev/null 2>&1 || warn "rc-update add 失败"
                rc-service forward start >/dev/null 2>&1 || true
            fi
            ;;
        sysvinit)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] 写入 %s; update-rc.d forward defaults\n' "$INIT_SCRIPT"
            else
                write_sysv_script
                if cmd_exists update-rc.d; then
                    update-rc.d forward defaults >/dev/null 2>&1 || warn "update-rc.d 失败"
                elif cmd_exists chkconfig; then
                    chkconfig --add forward >/dev/null 2>&1 || warn "chkconfig 失败"
                fi
            fi
            ;;
        *)
            warn "无法识别 init 系统, 跳过自启安装(请手动把 '$SELF_BIN apply' 加入开机脚本)"
            return 1
            ;;
    esac
    ok "开机自启已安装 ($init)"
    if [ "$(command -v "$PROG" 2>/dev/null)" != "$SELF_BIN" ]; then
        if [ "$DRY_RUN" != 1 ]; then
            warn "PATH 中启动不到 $SELF_BIN, 直接输入 $PROG 可能无效; 请确认 /usr/local/sbin 在 PATH 中"
        fi
    fi
    return 0
}

persist_remove() {
    need_root
    local init
    init=$(init_system)
    case "$init" in
        systemd)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] systemctl disable --now forward.service; rm -f %s\n' "$SYSTEMD_UNIT"
            else
                systemctl disable --now forward.service >/dev/null 2>&1 || true
                rm -f "$SYSTEMD_UNIT"
                systemctl daemon-reload >/dev/null 2>&1 || true
            fi
            ;;
        openrc)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] rc-update del forward default; rm -f %s\n' "$INIT_SCRIPT"
            else
                rc-update del forward default >/dev/null 2>&1 || true
                rc-service forward stop >/dev/null 2>&1 || true
                rm -f "$INIT_SCRIPT"
            fi
            ;;
        sysvinit)
            if [ "$DRY_RUN" = 1 ]; then
                printf '  [dry-run] 移除 %s\n' "$INIT_SCRIPT"
            else
                if cmd_exists update-rc.d; then
                    update-rc.d -f forward remove >/dev/null 2>&1 || true
                elif cmd_exists chkconfig; then
                    chkconfig --del forward >/dev/null 2>&1 || true
                fi
                rm -f "$INIT_SCRIPT"
            fi
            ;;
        *)
            warn "无法识别 init 系统, 请手动移除开机脚本"
            return 1
            ;;
    esac
    ok "开机自启已移除"
    return 0
}

#-------------------------------------------------------------------------------
# 交互菜单
#-------------------------------------------------------------------------------
confirm() {   # $1=提示
    [ "$ASSUME_YES" = 1 ] && return 0
    if [ ! -t 0 ]; then
        err "当前不是交互终端, 无法确认; 请显式加 --yes 表示同意"
        return 1
    fi
    local ans
    printf '%s' "$1" >&2
    read -r ans || return 1
    case "$ans" in
        y|Y|yes|YES|Yes|是) return 0 ;;
    esac
    return 1
}

ask() {   # $1=提示 $2=默认值 ; 输出到 stderr, 结果走 stdout
    local ans
    printf '%s' "$1" >&2
    read -r ans || return 1
    [ -z "$ans" ] && ans="${2:-}"
    printf '%s' "$ans"
}

ask_proto() {
    local p
    while :; do
        p=$(ask "协议 [tcp/udp/both] (默认 tcp): " "tcp") || return 1
        p=$(printf '%s' "$p" | tr 'A-Z' 'a-z')
        case "$p" in
            tcp|udp|both) printf '%s' "$p"; return 0 ;;
            *) warn "请输入 tcp / udp / both" ;;
        esac
    done
}

ask_port() {   # $1=提示
    local v
    while :; do
        v=$(ask "$1: ") || return 1
        if valid_port "$v"; then printf '%s' "$((10#$v))"; return 0; fi
        warn "端口无效(1-65535)"
    done
}

ask_ip() {
    local v
    while :; do
        v=$(ask "目标 IPv4 地址(127.0.0.1 表示本机端口): ") || return 1
        if valid_ipv4 "$v"; then printf '%s' "$v"; return 0; fi
        warn "IPv4 地址无效"
    done
}

menu_add() {
    local proto lp dip dp m=0 mode
    proto=$(ask_proto) || { info "已取消"; return 0; }
    lp=$(ask_port "监听端口(对外入口)") || { info "已取消"; return 0; }
    dip=$(ask_ip) || { info "已取消"; return 0; }
    dp=$(ask_port "目标端口") || { info "已取消"; return 0; }
    mode=$(rule_mode "$dip")
    if [ "$mode" = dnat ]; then
        if confirm "是否对转发的流量做地址伪装(SNAT)? 目标机默认网关指向本机时不需要 [y/N] "; then
            m=1
        fi
    fi
    case "$proto" in
        both)
            rule_add tcp "$lp" "$dip" "$dp" "$m"
            rule_add udp "$lp" "$dip" "$dp" "$m"
            ;;
        *)
            rule_add "$proto" "$lp" "$dip" "$dp" "$m"
            ;;
    esac
    ok "已添加: ${proto} ${lp} -> ${dip}:${dp} (SNAT=${m})"
    do_apply
}

menu_del() {
    local p lp dip dp m n=0 pick rule_lp rule_p
    if [ "$(count_rules)" -eq 0 ]; then
        info "当前没有规则"
        return 0
    fi
    while read -r p lp dip dp m; do
        n=$((n + 1))
        printf '  %2d) %-4s %-6s -> %s:%s\n' "$n" "$p" "$lp" "$dip" "$dp"
    done < <(norm_rules)
    pick=$(ask "请输入要删除的编号(0 取消): " "0") || return 0
    case "$pick" in
        ''|0|*[!0-9]*) info "已取消"; return 0 ;;
    esac
    if [ "$pick" -lt 1 ] || [ "$pick" -gt "$n" ]; then
        warn "编号超出范围"
        return 1
    fi
    rule_lp=""; rule_p=""
    n=0
    while read -r p lp dip dp m; do
        n=$((n + 1))
        if [ "$n" -eq "$pick" ]; then
            rule_lp="$lp"; rule_p="$p"
            break
        fi
    done < <(norm_rules)
    if rule_del "$rule_lp" "$rule_p"; then
        ok "已删除: ${rule_p} ${rule_lp}"
        do_apply
    else
        warn "删除失败"
    fi
}

show_summary() {
    local b ipfwd
    b=$(current_backend)
    ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null | tr -d ' ')
    printf '\n'
    printf '  当前后端    : %s\n' "${b:-未探测到}"
    printf '  ip_forward  : %s\n' "${ipfwd:-未知}"
    printf '  规则数量    : %s\n' "$(count_rules)"
    printf '  开机自启    : %s\n' "$(persist_enabled && echo 已启用 || echo 未启用)"
    printf '  配置文件    : %s\n' "$RULES_FILE"
    printf '\n'
}

menu_backend() {
    local b cur
    cur=$(current_backend)
    printf '\n  当前后端: %s\n' "${cur:-未探测到}"
    printf '  可选:\n'
    printf '    1) auto      自动(推荐)\n'
    printf '    2) iptables  iptables (含 iptables-nft 兼容层)\n'
    printf '    3) nft       原生 nftables\n'
    printf '    4) firewalld firewalld 永久规则\n'
    local pick
    pick=$(ask "请选择(0 取消): " "0") || return 0
    case "$pick" in
        1) b=auto ;;
        2) b=iptables ;;
        3) b=nft ;;
        4) b=firewalld ;;
        *) return 0 ;;
    esac
    if [ "$b" = iptables ] && firewalld_running; then
        warn "firewalld 正在运行, 它 reload 时会清掉 iptables 规则, 建议改用 firewalld 后端"
    fi
    state_set backend "$b"
    ok "后端已切换为: $b"
    do_apply
}

main_menu() {
    need_root
    local choice
    while :; do
        clear 2>/dev/null || true
        printf '\n'
        printf '  %s=== 端口转发管理 %sv%s%s ===%s\n' "$C_BLU" "$C_DIM" "$VERSION" "$C_BLU" "$C_RST"
        printf '  后端: %s\n' "$(current_backend || echo '未探测到')"
        printf '  规则: %s 条\n' "$(count_rules)"
        printf '  自启: %s\n' "$(persist_enabled && echo '已启用(重启自动恢复)' || echo '未启用')"
        printf '  ------------------------------------------------\n'
        printf '   1) 查看状态\n'
        printf '   2) 添加转发规则\n'
        printf '   3) 删除转发规则\n'
        printf '   4) 查看规则列表\n'
        printf '   5) 测试转发\n'
        printf '   6) 开机自启 / 卸载\n'
        printf '   7) 清空转发规则\n'
        printf '   8) 切换转发后端\n'
        printf '   0) 退出\n'
        printf '  ------------------------------------------------\n'
        if ! read -r -p "  请选择 [0-8]: " choice; then
            printf '\n'
            exit 0
        fi
        case "$choice" in
            1) do_status ;;
            2) menu_add ;;
            3) menu_del ;;
            4) do_list ;;
            5) do_test ;;
            6)
                if persist_enabled; then
                    info "开机自启已启用: 重启后自动恢复规则, 输入 $PROG 打开本面板"
                    if confirm "是否卸载开机自启(转发规则保留)? [y/N] "; then
                        if persist_remove; then
                            ok "已卸载开机自启; 当前转发规则仍然生效(重启后不再自动恢复)"
                        fi
                    fi
                else
                    persist_install && do_apply && ok "已装入开机自启; 以后输入 $PROG 即可打开本面板"
                fi
                ;;
            7) do_clear ;;
            8) menu_backend ;;
            0|q|Q) printf '\n'; exit 0 ;;
            *) ;;
        esac
        printf '\n'
        read -r -p "  按回车继续..." _ || { printf '\n'; exit 0; }
    done
}

#-------------------------------------------------------------------------------
# 命令行子命令
#-------------------------------------------------------------------------------
usage() {
    cat <<EOF
${PROG} ${VERSION} - Linux 端口转发管理工具 (iptables / nftables / firewalld)

用法:
  ${PROG} [子命令] [选项]
  ${PROG}                    进入交互菜单

子命令:
  add        添加转发规则        add -p tcp -l 8080 -d 10.0.0.5 -t 80
  del        删除转发规则        del 8080 [-p tcp]
  list       列出规则            list [--raw]
  apply      应用规则(立即生效)  apply
  clear      清空转发规则        clear [--yes] [--all]
  test       测试转发            test [监听端口]
  status     查看运行状态        status [--raw]
  backend    查看/切换后端       backend [auto|iptables|nft|firewalld]
  doctor     诊断: 打印后端原始规则(规则"识别不到"时用)
  import     收编内核里已有、但配置里没有的规则到 rules.conf
  install    安装开机自启        install
  uninstall  卸载(自启+程序, 规则保留) uninstall [--clear-rules] [--purge]
  menu       交互菜单

选项:
  -p, --proto <tcp|udp>    协议
  -l, --listen <端口>      监听端口(对外入口)
  -d, --dest <IPv4>        目标地址(127.0.0.1 = 本机端口)
  -t, --dport <端口>       目标端口
      --masq               对转发流量做 SNAT/MASQUERADE
      --backend <名称>     auto|iptables|nft|firewalld
      --zone <区域>        firewalld 区域(默认取 default zone)
  -q, --quiet              安静模式
  -y, --yes                所有确认自动回答 yes
  -n, --dry-run            只打印将执行的命令, 不改动系统
      --raw                机器可读输出
      --all                clear 时连不是本工具写入的规则一起清
      --clear-rules        uninstall 时连已下发的规则一起清(默认保留)
      --purge              卸载时连配置目录一起删除
      --no-color           禁用颜色
  -h, --help               显示帮助
  -V, --version            显示版本

规则文件:
  $RULES_FILE
  每行: <协议> <监听端口> <目标IP> <目标端口> [1=做SNAT]
  该文件是唯一事实来源, apply 会按文件内容重建自己的防火墙规则。

示例:
  ${PROG} add -p tcp -l 8080 -d 192.168.1.10 -t 80     # 8080 -> 192.168.1.10:80
  ${PROG} add -p udp -l 5353 -d 127.0.0.1 -t 53        # 本机端口转发
  ${PROG} del 8080
  ${PROG} --backend=nft apply                          # 指定后端
  ${PROG} install                                      # 重启后自动恢复

说明:
  * 只增删自己带注释标记的 iptables 规则 / 自己的 nft 表(ip forward),
    不会清空整张 nat 表, 不影响 Docker、ufw、Kubernetes。
  * 从本机连接 127.0.0.1:<入口端口> 不经过 PREROUTING, 无法验证 DNAT,
    请从其它机器测试。
EOF
}

cmd_add() {
    local proto="${OPT_PROTO:-}" lp="${OPT_LISTEN:-}" dip="${OPT_DEST:-}" dp="${OPT_DPORT:-}"
    local m=0 mode
    [ -n "$proto" ] || die "缺少 --proto (-p), 可选 tcp|udp"
    [ -n "$lp" ]    || die "缺少 --listen (-l) 监听端口"
    [ -n "$dip" ]   || die "缺少 --dest (-d) 目标地址"
    [ -n "$dp" ]    || die "缺少 --dport (-t) 目标端口"
    proto=$(printf '%s' "$proto" | tr 'A-Z' 'a-z')
    case "$proto" in tcp|udp) ;; *) die "协议必须是 tcp 或 udp" ;; esac
    valid_port "$lp" || die "监听端口无效: $lp"
    valid_port "$dp" || die "目标端口无效: $dp"
    valid_ipv4 "$dip" || die "目标地址无效: $dip"
    [ "${OPT_MASQ:-}" = 1 ] && m=1
    mode=$(rule_mode "$dip")
    [ "$mode" = local ] && m=0
    need_root
    if [ "$DRY_RUN" = 1 ]; then
        info "[dry-run] 将写入 $RULES_FILE: ${proto} $((10#$lp)) ${dip} $((10#$dp)) ${m}"
        info "[dry-run] 随后执行: $PROG apply"
        return 0
    fi
    local existed=0
    rule_key_exists "$proto" "$((10#$lp))" && existed=1
    rule_add "$proto" "$((10#$lp))" "$dip" "$((10#$dp))" "$m"
    if [ "$existed" = 1 ]; then
        ok "已更新: ${proto} ${lp} -> ${dip}:${dp} (SNAT=${m})"
    else
        ok "已添加: ${proto} ${lp} -> ${dip}:${dp} (SNAT=${m})"
    fi
    if ! do_apply; then
        warn "规则已保存到 $RULES_FILE, 但立即生效失败; 处理后端问题后再执行: $PROG apply"
        return 1
    fi
}

cmd_del() {
    local lp="${1:-}" proto="${OPT_PROTO:-}"
    [ -n "$lp" ] || die "用法: $PROG del <监听端口> [-p tcp|udp]"
    valid_port "$lp" || die "端口无效: $lp"
    need_root
    if [ "$DRY_RUN" = 1 ]; then
        info "[dry-run] 将从 $RULES_FILE 删除监听端口 ${lp} 的规则"
        info "[dry-run] 随后执行: $PROG apply"
        return 0
    fi
    if rule_del "$((10#$lp))" "$proto"; then
        ok "已删除监听端口 ${lp} 的规则"
        if ! do_apply; then
            warn "规则已从 $RULES_FILE 删除, 但防火墙规则同步失败; 请执行: $PROG apply"
            return 1
        fi
    else
        warn "没有找到监听端口 ${lp} 的规则"
        return 1
    fi
}

cmd_backend() {
    local arg="${1:-}"
    if [ -z "$arg" ]; then
        log "当前后端: $(current_backend)"
        log "可用: iptables=$([ "$(ipt_usable && echo 1 || echo 0)" = 1 ] && echo 是 || echo 否)" \
            " nft=$([ "$(nft_usable && echo 1 || echo 0)" = 1 ] && echo 是 || echo 否)" \
            " firewalld=$([ "$(firewalld_running && echo 1 || echo 0)" = 1 ] && echo 是 || echo 否)"
        return 0
    fi
    case "$arg" in
        auto|iptables|nft|firewalld) ;;
        *) die "后端必须是 auto|iptables|nft|firewalld" ;;
    esac
    need_root
    ensure_conf_dir
    state_set backend "$arg"
    ok "后端已设置为: $arg"
    do_apply
}

cmd_install() {
    need_root
    ensure_conf_dir
    persist_install || return 1
    do_apply
}

cmd_uninstall() {
    need_root
    local init p bin_state rule_state conf_state
    init=$(init_system)

    if [ "$ASSUME_YES" != 1 ] && [ -t 0 ]; then
        log "将要执行:"
        log "  1) 移除开机自启 ($init)"
        log "  2) 删除程序本体 $SELF_BIN (面板与命令都没了)"
        if [ "$OPT_CLEAR_RULES" = 1 ]; then
            log "  3) 清理已下发的转发规则 (--clear-rules)"
        else
            log "  3) 保留已下发的转发规则 (当前转发不受影响)"
        fi
        if [ "$OPT_PURGE" = 1 ]; then
            log "  4) 删除配置目录 $CONF_DIR"
        else
            log "  4) 保留配置 $RULES_FILE (重装后 apply 即可恢复)"
        fi
    fi
    if ! confirm "确认卸载? [y/N] "; then
        info "已取消"
        return 0
    fi

    persist_remove || warn "移除开机自启时出错, 继续"

    if [ "$OPT_CLEAR_RULES" = 1 ]; then
        if clear_firewall_rules; then
            if [ "$CLEAR_SKIPPED" = 1 ]; then
                rule_state="未清理(没有可用的防火墙后端)"
            else
                rule_state="已清理"
            fi
        else
            rule_state="清理出错, 请用 list 核对"
        fi
    else
        rule_state="保留(当前转发继续工作; 重启后不会自动恢复)"
    fi

    # 即使当前正运行的就是 $SELF_BIN, Linux 也允许 unlink 正在执行的脚本文件
    local removed=0 skipped=""
    if [ -e "$SELF_BIN" ] || [ -h "$SELF_BIN" ]; then
        if [ "$DRY_RUN" = 1 ]; then
            printf '  [dry-run] rm -f %s\n' "$SELF_BIN"
            bin_state="(dry-run 未删除)"
        elif rm -f -- "$SELF_BIN" 2>/dev/null; then
            info "已删除程序本体 $SELF_BIN"
            removed=$((removed + 1))
            bin_state="已删除"
        else
            warn "删除 $SELF_BIN 失败(权限不足?)"
            bin_state="仍存在"
        fi
    else
        bin_state="不存在"
    fi

    # 再清掉 PATH 里其它位置的副本(手工拷到 /usr/local/bin 等), 否则"卸载了还能用"
    local cp
    while IFS= read -r cp; do
        [ -n "$cp" ] || continue
        [ "$cp" = "$SELF_BIN" ] && continue
        if [ "$DRY_RUN" = 1 ]; then
            printf '  [dry-run] rm -f %s\n' "$cp"
            continue
        fi
        if rm -f -- "$cp" 2>/dev/null; then
            info "已删除副本 $cp"
            removed=$((removed + 1))
        else
            warn "删除副本 $cp 失败(权限不足?)"
            skipped="$skipped $cp"
        fi
    done <<EOF2
$(tool_copies)
EOF2
    [ "$removed" -gt 0 ] && bin_state="已删除(${removed} 个文件)"
    hash -r 2>/dev/null || true

    # PATH 里还有别的同名命令时, 用户会以为"没卸载干净"/"forward 还能用"
    p=$(command -v forward 2>/dev/null || true)
    if [ -n "$p" ] && [ "$p" != "$SELF_BIN" ] && [ -f "$p" ]; then
        warn "PATH 中还有另一个 forward: $p"
        warn "  它不是本工具安装的(可能是别的软件或手工拷贝), 输入 forward 会启动它; 如不需要请自行删除"
    elif [ -n "$p" ] && [ ! -f "$p" ]; then
        # 文件已删, 但本次进程的命令缓存里还留着旧路径(极少见)
        warn "命令缓存里还留着 $p (文件已删除), 执行 hash -r 即可清掉"
    elif [ -n "$skipped" ]; then
        warn "以下副本删除失败:$skipped"
    fi
    # 别名/函数也可能让 forward 继续可用
    if cmd_exists alias 2>/dev/null && alias forward >/dev/null 2>&1; then
        warn "当前 shell 里有 alias forward, 请执行 unalias forward 或重开终端"
    fi

    if [ "$OPT_PURGE" = 1 ]; then
        # 只删我们自己的配置目录; 明显危险或非绝对路径的一律拒绝
        case "$CONF_DIR" in
            ""|/|/etc|/usr|/usr/local|/usr/local/etc|/var|/root|/home)
                err "配置目录看起来是系统目录, 拒绝自动删除: $CONF_DIR"
                conf_state="保留"
                ;;
            /*/*)
                if [ "$DRY_RUN" = 1 ]; then
                    printf '  [dry-run] rm -rf %s\n' "$CONF_DIR"
                    conf_state="(dry-run 未删除)"
                else
                    rm -rf -- "$CONF_DIR" && conf_state="已删除" || { warn "删除 $CONF_DIR 失败"; conf_state="仍存在"; }
                fi
                ;;
            *)
                err "配置目录不是绝对路径, 拒绝自动删除: $CONF_DIR"
                conf_state="保留"
                ;;
        esac
    else
        conf_state="$([ -f "$RULES_FILE" ] && echo "保留 $RULES_FILE" || echo "无")"
    fi

    log ""
    ok "卸载完成"
    log "  开机自启 : 已移除"
    log "  程序本体 : $bin_state"
    log "  内核规则 : $rule_state"
    log "  配置文件 : $conf_state"
    if [ "$OPT_PURGE" != 1 ] && [ -f "$RULES_FILE" ]; then
        log ""
        log "  注意: 开机自启已移除, 重启后规则不会自动恢复(内核规则本身不跨重启)。"
        log "        当前正在转发的流量不受影响; 需要再次使用时, 用原脚本重新安装:"
        log "        sudo bash forward.sh install"
    fi
    if [ "$removed" -gt 0 ]; then
        log "  提示: 如果当前终端里输入 forward 还有反应, 执行 hash -r 或重开终端即可。"
    fi
    return 0
}

#-------------------------------------------------------------------------------
# 入口
#-------------------------------------------------------------------------------
parse_args() {
    local arg
    while [ $# -gt 0 ]; do
        arg="$1"
        case "$arg" in
            -h|--help)    usage; exit 0 ;;
            -V|--version) printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
            -q|--quiet)   QUIET=1 ;;
            -y|--yes)     ASSUME_YES=1 ;;
            -n|--dry-run) DRY_RUN=1 ;;
            --raw)        RAW=1 ;;
            --no-color)   NO_COLOR_OPT=1 ;;
            --masq)       OPT_MASQ=1 ;;
            --keep-rules) OPT_CLEAR_RULES=0 ;;   # 兼容旧参数: 卸载默认就保留规则
            --clear-rules) OPT_CLEAR_RULES=1 ;;
            --all)        OPT_ALL=1 ;;
            --purge)      OPT_PURGE=1 ;;
            --backend)    shift; OPT_BACKEND="${1:-}"; [ -n "$OPT_BACKEND" ] || die "--backend 需要参数" ;;
            --backend=*)  OPT_BACKEND="${arg#*=}" ;;
            --zone)       shift; OPT_ZONE="${1:-}" ;;
            --zone=*)     OPT_ZONE="${arg#*=}" ;;
            --proto|-p)   shift; OPT_PROTO="${1:-}" ;;
            --proto=*)    OPT_PROTO="${arg#*=}" ;;
            --listen|-l)  shift; OPT_LISTEN="${1:-}" ;;
            --listen=*)   OPT_LISTEN="${arg#*=}" ;;
            --dest|-d)    shift; OPT_DEST="${1:-}" ;;
            --dest=*)     OPT_DEST="${arg#*=}" ;;
            --dport|-t)   shift; OPT_DPORT="${1:-}" ;;
            --dport=*)    OPT_DPORT="${arg#*=}" ;;
            --)           shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done; return 0 ;;
            -*)           die "未知选项: $arg (用 --help 查看用法)" ;;
            *)            POSITIONAL+=("$arg") ;;
        esac
        [ $# -gt 0 ] || break
        shift
    done
    return 0
}

warn_stale_install() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ -f "$SELF_BIN" ] || return 0
    local me iv
    me=$(self_path)
    [ "$me" = "$SELF_BIN" ] && return 0
    cmp -s "$me" "$SELF_BIN" 2>/dev/null && return 0
    iv=$(tool_version_of "$SELF_BIN")
    warn "注意: $SELF_BIN 里装的是另一个版本 (${iv:-未知} / 当前 ${VERSION})"
    warn "      直接输入 $PROG 运行的是那一份; 执行 'sudo $PROG install' 可覆盖为当前版本"
}

main() {
    parse_args "$@"
    init_colors
    local cmd=""
    if [ "${#POSITIONAL[@]}" -gt 0 ]; then
        cmd="${POSITIONAL[0]}"
    fi

    case "$cmd" in
        ""|menu|add|del|delete|list|ls|clear|flush|test|status|info|doctor|diag|import|adopt)
            warn_stale_install ;;
    esac

    if [ -z "$cmd" ]; then
        if [ ! -t 0 ]; then
            die "未指定子命令且标准输入不是终端。请用: $PROG --help"
        fi
        main_menu
        return 0
    fi

    case "$cmd" in
        add)        cmd_add ;;
        del|delete|rm) cmd_del "${POSITIONAL[1]:-}" ;;
        list|ls)    do_list ;;
        apply)      do_apply ;;
        clear|flush) do_clear ;;
        test)       do_test "${POSITIONAL[1]:-}" ;;
        status|info) do_status ;;
        backend)    cmd_backend "${POSITIONAL[1]:-}" ;;
        doctor|diag) do_doctor ;;
        import|adopt) do_import ;;
        install)    cmd_install ;;
        uninstall)  cmd_uninstall ;;
        menu)       main_menu ;;
        help)       usage; exit 0 ;;
        *)          err "未知子命令: $cmd"; err "用 '$PROG --help' 查看用法"; exit 1 ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    main "$@"
fi
