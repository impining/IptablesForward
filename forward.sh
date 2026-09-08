#!/bin/bash

# 颜色定义
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

# 检查 Root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}[!] 错误：此脚本必须以 root 权限运行。${RESET}"
    echo -e "请使用: sudo bash $0"
    exit 1
fi

# 1. 检测并开启系统的 IP 转发功能 (IP Forwarding)
check_and_enable_ip_forward() {
    echo -e "\n${YELLOW}[1/3] 正在检查系统 IP 转发状态...${RESET}"
    ip_forward_status=$(sysctl -n net.ipv4.ip_forward)

    if [ "$ip_forward_status" -eq 1 ]; then
        echo -e "${GREEN}[√] 系统 IP 转发已开启，无需重复开启。${RESET}"
    else
        echo -e "${YELLOW}[!] 系统未开启 IP 转发，正在尝试开启...${RESET}"
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        
        # 写入配置文件，确保重启后依然生效
        if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
        else
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        fi
        sysctl -p > /dev/null 2>&1
        echo -e "${GREEN}[√] 系统 IP 转发已成功开启！${RESET}"
    fi
}

# 2. 配置 iptables 端口转发规则
add_port_forward() {
    check_and_enable_ip_forward

    echo -e "\n${YELLOW}[2/3] 请输入转发参数:${RESET}"
    read -p "请输入 本机端口 (a): " a
    read -p "请输入 目标 IP (b): " b
    read -p "请输入 目标端口 (c): " c

    # 简单参数校验
    if [[ -z "$a" || -z "$b" || -z "$c" ]]; then
        echo -e "${RED}[!] 错误：参数不能为空，操作取消。${RESET}"
        return
    fi

    echo -e "\n正在添加 iptables 规则: 本机:$a -> $b:$c ..."

    # 允许 POSTROUTING NAT 伪装
    iptables -t nat -A POSTROUTING -j MASQUERADE
    
    # 添加 PREROUTING 目标地址转换规则 (TCP/UDP 同时转发)
    iptables -t nat -A PREROUTING -p tcp --dport "$a" -j DNAT --to-destination "$b:$c"
    iptables -t nat -A PREROUTING -p udp --dport "$a" -j DNAT --to-destination "$b:$c"

    # 允许 FORWARD 链放行
    iptables -A FORWARD -p tcp -d "$b" --dport "$c" -j ACCEPT
    iptables -A FORWARD -p udp -d "$b" --dport "$c" -j ACCEPT

    echo -e "${GREEN}[√] 转发规则添加完成！${RESET}"

    # 自动触发测试
    test_port_forward "$a" "$b" "$c"
}

# 3. 测试转发连通性
test_port_forward() {
    local local_port=$1
    local target_ip=$2
    local target_port=$3

    # 如果没有传入参数，则提示用户手动输入测试参数
    if [[ -z "$local_port" || -z "$target_ip" || -z "$target_port" ]]; then
        echo -e "\n${YELLOW}=== 测试转发连通性 ===${RESET}"
        read -p "请输入要测试的 本机端口 (a): " local_port
        read -p "请输入要测试的 目标 IP (b): " target_ip
        read -p "请输入要测试的 目标端口 (c): " target_port
    fi

    echo -e "\n${YELLOW}[3/3] 正在测试连通性 (测试目标: $target_ip:$target_port)...${RESET}"

    # 优先选择 nc (netcat) 进行测试，若无则退回使用 curl/timeout
    if command -v nc &>/dev/null; then
        nc -z -w 3 "$target_ip" "$target_port" &>/dev/null
        res=$?
    else
        # 利用 bash 内置的 /dev/tcp 进行端口连通测试 (超时时间 3 秒)
        timeout 3 bash -c "</dev/tcp/$target_ip/$target_port" &>/dev/null
        res=$?
    fi

    echo -n "测试结果: "
    if [ $res -eq 0 ]; then
        echo -e "${GREEN}通${RESET}"
    else
        echo -e "${RED}不通${RESET}"
        echo -e "${YELLOW}(提示: 如果显示“不通”，请检查目标主机防火墙设置、目标端口服务是否正在运行，或云厂商安全组是否放行了 $target_port 端口)${RESET}"
    fi
}

# 查看现有转发规则
list_rules() {
    echo -e "\n${YELLOW}=== 当前 iptables NAT 转发规则 ===${RESET}"
    iptables -t nat -L PREROUTING -n --line-numbers | grep -E "dpt|DNAT"
}

# 清理全部 NAT 转发规则
clear_rules() {
    echo -e "\n${YELLOW}正在清理所有的 NAT 规则...${RESET}"
    iptables -t nat -F
    echo -e "${GREEN}[√] 已清空 NAT 规则！${RESET}"
}

# 交互式主菜单
main_menu() {
    while true; do
        echo -e "\n${GREEN}========================================${RESET}"
        echo -e "${GREEN}       Linux iptables 端口转发工具      ${RESET}"
        echo -e "${GREEN}========================================${RESET}"
        echo -e " 1. 开启 IP 流量转发检查"
        echo -e " 2. 添加端口转发规则 (a端口 -> bIP:c端口)"
        echo -e " 3. 测试端口转发连通性"
        echo -e " 4. 查看当前转发规则"
        echo -e " 5. 清空所有 NAT 规则"
        echo -e " 0. 退出脚本"
        echo -e "${GREEN}----------------------------------------${RESET}"
        read -p "请输入选项 [0-5]: " choice

        case "$choice" in
            1) check_and_enable_ip_forward ;;
            2) add_port_forward ;;
            3) test_port_forward ;;
            4) list_rules ;;
            5) clear_rules ;;
            0) echo "已退出。"; exit 0 ;;
            *) echo -e "${RED}[!] 无效选项，请重新输入！${RESET}" ;;
        esac
    done
}

# 启动菜单
main_menu
