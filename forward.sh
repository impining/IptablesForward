#!/bin/bash
#
# Linux 端口转发工具（nft / iptables 后端自动适配）
# 适配环境: table ip nat + table ip filter (FORWARD 链, 大写)
# 修复: 去重子shell失效、IPv4校验、正则转义、误导性测试、清理警告
#

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

BACKEND=""
NFT_TABLE="ip nat"

# ================= 后端检测 =================
detect_backend() {
    local ver
    ver=$(iptables --version 2>/dev/null)
    if echo "$ver" | grep -q "nf_tables"; then
        BACKEND="nft"
        echo -e "${CYAN}[i] 后端: nftables (iptables 为 nf_tables 兼容层)${RESET}"
    elif echo "$ver" | grep -q "legacy"; then
        BACKEND="iptables"
        echo -e "${CYAN}[i] 后端: iptables-legacy${RESET}"
    else
        if command -v nft &>/dev/null && nft list tables &>/dev/null; then
            BACKEND="nft"
            echo -e "${CYAN}[i] 后端: nftables (兜底判断)${RESET}"
        else
            BACKEND="iptables"
            echo -e "${CYAN}[i] 后端: iptables (兜底判断)${RESET}"
        fi
    fi
}

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}[!] 此脚本必须以 root 运行。${RESET}"
    exit 1
fi

detect_backend

# ================= IP 转发 =================
check_and_enable_ip_forward() {
    echo -e "\n${YELLOW}[1/3] 检查 IP 转发...${RESET}"
    local status
    status=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [ "$status" = "1" ]; then
        echo -e "${GREEN}[√] IP 转发已开启。${RESET}"
    else
        echo -e "${YELLOW}[!] 正在开启 IP 转发...${RESET}"
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
        else
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        fi
        sysctl -p > /dev/null 2>&1
        echo -e "${GREEN}[√] IP 转发已开启并持久化。${RESET}"
    fi
}

# ================= 校验 =================
validate_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# 修复: 先整体正则匹配，再校验段数，再逐段校验纯数字和范围
validate_ipv4() {
    local ip=$1
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local IFS='.'
    local -a o=($ip)
    [ "${#o[@]}" -eq 4 ] || return 1
    local x
    for x in "${o[@]}"; do
        [[ "$x" =~ ^[0-9]+$ ]] || return 1
        [ "$x" -ge 0 ] && [ "$x" -le 255 ] || return 1
    done
    return 0
}

# 修复: 转义 IP 中的点，供 grep -E 使用
escape_dots() {
    echo "$1" | sed 's/\./\\./g'
}

# ================= nft: FORWARD 放行 =================
ensure_nft_forward_accept() {
    local tip=$1
    local tport=$2
    local fchain="FORWARD"
    local existing tip_esc
    tip_esc=$(escape_dots "$tip")

    nft list table ip filter &>/dev/null || nft add table ip filter
    if ! nft list chain ip filter "$fchain" &>/dev/null; then
        nft add chain ip filter "$fchain" '{ type filter hook forward priority filter; policy accept; }'
    fi

    existing=$(nft list chain ip filter "$fchain" 2>/dev/null)

    if ! echo "$existing" | grep -qE "ip daddr $tip_esc tcp dport $tport\b"; then
        nft add rule ip filter "$fchain" ip daddr "$tip" tcp dport "$tport" counter accept
        echo -e "${GREEN}  + FORWARD 放行 TCP $tip:$tport${RESET}"
    fi
    if ! echo "$existing" | grep -qE "ip daddr $tip_esc udp dport $tport\b"; then
        nft add rule ip filter "$fchain" ip daddr "$tip" udp dport "$tport" counter accept
        echo -e "${GREEN}  + FORWARD 放行 UDP $tip:$tport${RESET}"
    fi
    # 回程兼容 { established, related } 和 established,related
    if ! echo "$existing" | grep -qE "ct state .*(established|related)"; then
        nft add rule ip filter "$fchain" ct state established,related accept
        echo -e "${GREEN}  + FORWARD 回程放行 (established,related)${RESET}"
    fi
}

# ================= 添加转发 =================
add_port_forward() {
    check_and_enable_ip_forward

    echo -e "\n${YELLOW}[2/3] 输入转发参数:${RESET}"
    read -p "本机端口 (a): " a
    read -p "目标 IP (b): " b
    read -p "目标端口 (c): " c

    if ! validate_port "$a"; then
        echo -e "${RED}[!] 本机端口非法 (1-65535)。${RESET}"; return
    fi
    if ! validate_ipv4 "$b"; then
        echo -e "${RED}[!] 目标 IP 非法 IPv4。${RESET}"; return
    fi
    if ! validate_port "$c"; then
        echo -e "${RED}[!] 目标端口非法 (1-65535)。${RESET}"; return
    fi

    echo -e "\n添加规则: 本机:$a -> $b:$c ..."

    if [ "$BACKEND" = "nft" ]; then
        nft list table $NFT_TABLE &>/dev/null || nft add table $NFT_TABLE
        nft list chain $NFT_TABLE prerouting &>/dev/null || \
            nft add chain $NFT_TABLE prerouting '{ type nat hook prerouting priority dstnat; }'
        nft list chain $NFT_TABLE postrouting &>/dev/null || \
            nft add chain $NFT_TABLE postrouting '{ type nat hook postrouting priority srcnat; }'

        local existing_nat b_esc
        existing_nat=$(nft list table $NFT_TABLE 2>/dev/null)
        b_esc=$(escape_dots "$b")

        if ! echo "$existing_nat" | grep -qE "tcp dport $a\b.*dnat to $b_esc:$c\b"; then
            nft add rule $NFT_TABLE prerouting tcp dport "$a" dnat to "$b:$c"
            echo -e "${GREEN}  + DNAT TCP :$a -> $b:$c${RESET}"
        else
            echo -e "${YELLOW}  = DNAT TCP :$a -> $b:$c 已存在，跳过${RESET}"
        fi
        if ! echo "$existing_nat" | grep -qE "udp dport $a\b.*dnat to $b_esc:$c\b"; then
            nft add rule $NFT_TABLE prerouting udp dport "$a" dnat to "$b:$c"
            echo -e "${GREEN}  + DNAT UDP :$a -> $b:$c${RESET}"
        else
            echo -e "${YELLOW}  = DNAT UDP :$a -> $b:$c 已存在，跳过${RESET}"
        fi

        if ! echo "$existing_nat" | grep -qE "ip daddr $b_esc tcp dport $c\b.*masquerade"; then
            nft add rule $NFT_TABLE postrouting ip daddr "$b" tcp dport "$c" masquerade
            echo -e "${GREEN}  + MASQ TCP $b:$c${RESET}"
        fi
        if ! echo "$existing_nat" | grep -qE "ip daddr $b_esc udp dport $c\b.*masquerade"; then
            nft add rule $NFT_TABLE postrouting ip daddr "$b" udp dport "$c" masquerade
            echo -e "${GREEN}  + MASQ UDP $b:$c${RESET}"
        fi

        ensure_nft_forward_accept "$b" "$c"

    else
        iptables -t nat -C POSTROUTING -d "$b" -p tcp --dport "$c" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -d "$b" -p tcp --dport "$c" -j MASQUERADE
        iptables -t nat -C POSTROUTING -d "$b" -p udp --dport "$c" -j MASQUERADE 2>/dev/null || \
            iptables -t nat -A POSTROUTING -d "$b" -p udp --dport "$c" -j MASQUERADE

        iptables -t nat -C PREROUTING -p tcp --dport "$a" -j DNAT --to-destination "$b:$c" 2>/dev/null || \
            iptables -t nat -A PREROUTING -p tcp --dport "$a" -j DNAT --to-destination "$b:$c"
        iptables -t nat -C PREROUTING -p udp --dport "$a" -j DNAT --to-destination "$b:$c" 2>/dev/null || \
            iptables -t nat -A PREROUTING -p udp --dport "$a" -j DNAT --to-destination "$b:$c"

        iptables -C FORWARD -p tcp -d "$b" --dport "$c" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -p tcp -d "$b" --dport "$c" -j ACCEPT
        iptables -C FORWARD -p udp -d "$b" --dport "$c" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -p udp -d "$b" --dport "$c" -j ACCEPT
        iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    echo -e "${GREEN}[√] 添加完成。${RESET}"
    echo -e "${YELLOW}[i] 验证请从另一台机器访问 本机IP:$a（本机自测有局限，见选项 3）${RESET}"
}

# ================= 抓取 DNAT 映射（返回纯文本，供展示和测试复用） =================
gather_dnat_mapping() {
    local rules=""
    if [ "$BACKEND" = "nft" ]; then
        rules=$(nft list table $NFT_TABLE 2>/dev/null | \
            grep -E 'dnat to [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | \
            sed -E 's/.*(tcp|udp) dport ([0-9]+).*dnat to ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+).*/\2 \3 \4/' | \
            sort -u)
    else
        rules=$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | \
            grep -i "DNAT" | awk '{
                lport=""; tip=""; tport="";
                for(i=1; i<=NF; i++){
                    if ($i ~ /^dpt:/) { split($i, a, ":"); lport=a[2] }
                    else if ($i == "dpt:" && $(i+1) ~ /^[0-9]+$/) { lport=$(i+1) }
                    if ($i ~ /^to:/) { split($i, b, ":"); tip=b[2]; tport=b[3] }
                    else if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$/) {
                        split($i, c, ":"); tip=c[1]; tport=c[2]
                    }
                }
                if (lport != "" && tip != "" && tport != "") print lport" "tip" "tport
            }' | sort -u)
    fi
    echo "$rules"
}

# ================= 获取本机出口/内网 IP（用于提示测试地址） =================
get_local_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

# ================= 展示映射 + 正确测试方法 =================
show_dnat_mapping() {
    echo -e "\n${YELLOW}=== 当前 DNAT 映射 ===${RESET}"
    local rules
    rules=$(gather_dnat_mapping)

    if [ -z "$rules" ]; then
        echo -e "${RED}[!] 未抓到 DNAT 规则。${RESET}"
        echo -e "${YELLOW}（可能尚未添加转发，或规则不在 nat 表 PREROUTING 链中）${RESET}"
        return
    fi

    # 修复: 进程替换让 while 在父 shell 运行，去重生效
    local seen="" unique=""
    while read -r lp tip tp; do
        local key="${lp}-${tip}-${tp}"
        if echo " $seen " | grep -qF " $key "; then
            continue
        fi
        seen="$seen $key"
        unique="${unique}${lp} ${tip} ${tp}"$'\n'
    done < <(echo "$rules")

    echo -e "${GREEN}入口端口 -> 目标地址${RESET}"
    while read -r lp tip tp; do
        [ -z "$lp" ] && continue
        echo -e "  ${CYAN}$lp${RESET} -> ${CYAN}$tip:$tp${RESET}"
    done < <(echo "$unique")

    local lip
    lip=$(get_local_ip)
    [ -z "$lip" ] && lip="<本机IP>"

    echo -e "\n${YELLOW}[i] 正确的验证方法：${RESET}"
    echo -e "  ${GREEN}方法 A（推荐，真正验证转发）${RESET}"
    echo -e "    从另一台机器执行： nc -zv $lip <入口端口>"
    echo -e "    例如入口 12492：  nc -zv $lip 12492"
    echo -e "    通了说明 DNAT 转发链路正常。"
    echo -e ""
    echo -e "  ${GREEN}方法 B（本机自测，有局限）${RESET}"
    echo -e "    nc -zv 127.0.0.1 <入口端口>"
    echo -e "    ${RED}注意：本机访问本机 IP/回环时，包走 OUTPUT 链，不经过 PREROUTING，${RESET}"
    echo -e "    ${RED}DNAT 不会对这类包生效，所以“本机自测不通”不代表转发坏了。${RESET}"
    echo -e "    ${RED}它只能证明本机入口端口上有没有进程/规则响应。${RESET}"
    echo -e ""
    echo -e "  ${GREEN}方法 C（看计数）${RESET}"
    echo -e "    nft list table $NFT_TABLE   # 看 postrouting masquerade 的 counter 是否增长"
    echo -e "    ${YELLOW}有外部流量经过时 counter 增长，即证明转发在工作。${RESET}"
}

# ================= 查看规则 =================
list_rules() {
    echo -e "\n${YELLOW}=== 当前 NAT 转发规则 ===${RESET}"
    if [ "$BACKEND" = "nft" ]; then
        echo -e "${GREEN}--- nft 表 $NFT_TABLE ---${RESET}"
        nft list table $NFT_TABLE 2>/dev/null || echo "（表不存在）"
        echo -e "\n${GREEN}--- nft 表 ip filter FORWARD ---${RESET}"
        nft list chain ip filter FORWARD 2>/dev/null || echo "（链不存在）"
    else
        echo -e "${GREEN}--- PREROUTING (DNAT) ---${RESET}"
        iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null
        echo -e "\n${GREEN}--- POSTROUTING (MASQUERADE) ---${RESET}"
        iptables -t nat -L POSTROUTING -n -v --line-numbers 2>/dev/null
        echo -e "\n${GREEN}--- FORWARD ---${RESET}"
        iptables -L FORWARD -n -v --line-numbers 2>/dev/null
    fi
}

# ================= 清理 =================
clear_rules() {
    echo -e "\n${RED}[!] 即将清空 NAT 表规则。${RESET}"
    echo -e "${RED}    注意：会删除该表中【所有】规则，包括非本脚本添加的。${RESET}"
    echo -e "${YELLOW}    不含 FORWARD 链。${RESET}"
    read -p "确认？(y/N): " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

    if [ "$BACKEND" = "nft" ]; then
        nft flush table $NFT_TABLE 2>/dev/null && echo -e "${GREEN}[√] nft 表 $NFT_TABLE 已清空。${RESET}"
    else
        iptables -t nat -F && echo -e "${GREEN}[√] iptables nat 表已清空。${RESET}"
    fi
    echo -e "${YELLOW}[i] FORWARD 链规则未动，如需清理请手动处理。${RESET}"
}

# ================= 退出 =================
exit_script() {
    echo -e "${GREEN}已退出。${RESET}"
    exit 0
}

# ================= 主菜单 =================
main_menu() {
    while true; do
        echo -e "\n${GREEN}========================================${RESET}"
        echo -e "${GREEN}   Linux 端口转发工具 (后端: $BACKEND)   ${RESET}"
        echo -e "${GREEN}========================================${RESET}"
        echo -e " 1. 检查/开启 IP 转发"
        echo -e " 2. 添加端口转发规则 (a -> b:c)"
        echo -e " 3. 查看 DNAT 映射 + 正确验证方法"
        echo -e " 4. 查看当前 NAT / FORWARD 规则"
        echo -e " 5. 清空 NAT 规则"
        echo -e " 0. 退出"
        echo -e "${GREEN}----------------------------------------${RESET}"
        read -p "选项 [0-5]: " choice
        case "$choice" in
            1) check_and_enable_ip_forward ;;
            2) add_port_forward ;;
            3) show_dnat_mapping ;;
            4) list_rules ;;
            5) clear_rules ;;
            0) exit_script ;;
            *) echo -e "${RED}[!] 无效选项。${RESET}" ;;
        esac
    done
}

main_menu
