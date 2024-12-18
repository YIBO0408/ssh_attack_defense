#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "该脚本需以 root 用户运行！"
    exit
fi

function failed_ips() {
    echo "登录失败的 IP（最多 10 个）:"
    lastb | awk '{if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $3}' | \
    sort | uniq -c | sort -nr | head -n 10
    read -p "按任意键继续..."
}

function failed_users() {
    echo "登录失败的用户（最多 10 个）:"
    lastb | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 10
    read -p "按任意键继续..."
}

function successful_ips() {
    echo "登录成功的 IP（前 10 个）:"
    grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | head -n 10
    read -p "按任意键继续..."
}

function successful_users() {
    echo "登录成功的用户（前 10 个）:"
    grep "Accepted" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | head -n 10
    read -p "按任意键继续..."
}

function failed_time_analysis() {
    echo "登录失败时间段分析（月日时统计，前 30 个）："
    grep "Failed password" /var/log/auth.log | \
        awk '{print $1, $2, $3, substr($0, index($0,$3)+4,2)}' | \
        awk '{printf "%s %s %02d 时\n", $1, $2, $3, $4}' | \
        sort | uniq -c | sort -nr | head -n 30
    read -p "按任意键继续..."
}

function block_malicious_ips() {
    local threshold=10
    echo "登录失败次数超过 ${threshold} 次的恶意 IP:"
    malicious_ips=$(lastb | awk '{if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $3}' | sort | uniq -c | awk -v limit=${threshold} '$1 >= limit {print $2}')
    
    if [ -z "$malicious_ips" ]; then
        echo "没有恶意 IP 需要封禁！"
        read -p "按任意键继续..."
        return
    fi
    
    echo "$malicious_ips" | nl -w2 -s'. '
    
    echo ""
    
    read -p "请输入要封禁的 IP 序号，多个 IP 用逗号分隔（例如: 1,3,5），输入 'q' 退出: " ip_choice

    if [ "$ip_choice" == "q" ]; then
        echo "取消操作。"
        read -p "按任意键继续..."
        return
    fi

    for ip_num in $(echo $ip_choice | tr ',' ' '); do
        ip=$(echo "$malicious_ips" | sed -n "${ip_num}p" | awk '{print $2}')
        if [ -n "$ip" ]; then
            echo "封禁 IP: ${ip}"
            iptables -A INPUT -s ${ip} -j DROP
        fi
    done

    echo "封禁完成！"
    read -p "按任意键继续..."
}

function unblock_ip() {
    blocked_ips=$(iptables -L INPUT -n --line-numbers | grep "DROP" | awk '{print $1, $4}')

    if [ -z "${blocked_ips}" ]; then
        echo "没有被封禁的 IP"
    else
        echo "当前被封禁的 IP:"
        echo "${blocked_ips}"
        read -p "请输入要解封的 IP (输入取消): " ip
        if [ -n "${ip}" ]; then
            iptables -D INPUT -s ${ip} -j DROP
            echo "已解封 IP: ${ip}"
        else
            echo "取消操作。"
        fi
    fi
    read -p "按任意键继续..."
}

function view_ssh_config() {
    echo -e "\n当前 SSH 配置信息:"

    grep -E "^[^#]" /etc/ssh/sshd_config | sed '/^\s*$/d' > /tmp/ssh_config_cleaned

    echo -e "\n【/etc/ssh/sshd_config 配置】: "
    while IFS= read -r line; do
        case $line in
            PermitRootLogin*) 
                echo -e "  \033[1;32mPermitRootLogin:\033[0m $line   \033[1;33m# 是否允许 root 用户登录\033[0m" ;;
            PubkeyAuthentication*) 
                echo -e "  \033[1;32mPubkeyAuthentication:\033[0m $line   \033[1;33m# 是否启用公钥认证\033[0m" ;;
            PasswordAuthentication*) 
                echo -e "  \033[1;32mPasswordAuthentication:\033[0m $line   \033[1;33m# 是否允许密码登录\033[0m" ;;
            Port*) 
                echo -e "  \033[1;32mPort:\033[0m $line   \033[1;33m# SSH 服务端口号\033[0m" ;;
            AllowUsers*) 
                echo -e "  \033[1;32mAllowUsers:\033[0m $line   \033[1;33m# 允许登录的用户列表\033[0m" ;;
            DenyUsers*) 
                echo -e "  \033[1;32mDenyUsers:\033[0m $line   \033[1;33m# 禁止登录的用户列表\033[0m" ;;
            *)
                echo -e "  $line" ;;
        esac
    done < /tmp/ssh_config_cleaned
    echo -e "\n"

    rm -f /tmp/ssh_config_cleaned

    if [ -f /etc/ssh/sshd_config_external ]; then
        echo -e "\n【/etc/ssh/sshd_config_external 配置】: "
        grep -E "^[^#]" /etc/ssh/sshd_config_external | sed '/^\s*$/d' > /tmp/ssh_external_config_cleaned

        while IFS= read -r line; do
            case $line in
                PermitRootLogin*) 
                    echo -e "  \033[1;32mPermitRootLogin:\033[0m $line   \033[1;33m# 是否允许 root 用户登录\033[0m" ;;
                PubkeyAuthentication*) 
                    echo -e "  \033[1;32mPubkeyAuthentication:\033[0m $line   \033[1;33m# 是否启用公钥认证\033[0m" ;;
                PasswordAuthentication*) 
                    echo -e "  \033[1;32mPasswordAuthentication:\033[0m $line   \033[1;33m# 是否允许密码登录\033[0m" ;;
                Port*) 
                    echo -e "  \033[1;32mPort:\033[0m $line   \033[1;33m# SSH 服务端口号\033[0m" ;;
                AllowUsers*) 
                    echo -e "  \033[1;32mAllowUsers:\033[0m $line   \033[1;33m# 允许登录的用户列表\033[0m" ;;
                DenyUsers*) 
                    echo -e "  \033[1;32mDenyUsers:\033[0m $line   \033[1;33m# 禁止登录的用户列表\033[0m" ;;
                *)
                    echo -e "  $line" ;;
            esac
        done < /tmp/ssh_external_config_cleaned
        rm -f /tmp/ssh_external_config_cleaned
    else
        echo -e "\n\033[1;31m警告: /etc/ssh/sshd_config_external 文件不存在！\033[0m"
    fi

    echo -e "\n\033[1;36m注: 所有显示的设置均来自相应的 SSH 配置文件\033[0m"
    read -p "按任意键继续..."
}

function login_summary() {
    total_success=$(grep "Accepted password" /var/log/auth.log | wc -l)
    total_failed=$(grep "Failed password" /var/log/auth.log | wc -l)
    total_attempts=$((total_success + total_failed))

    echo "登录统计概览:"
    echo "总尝试次数: ${total_attempts}"
    echo "成功次数: ${total_success}"
    echo "失败次数: ${total_failed}"
    echo "失败比例: $(awk "BEGIN {printf \"%.2f%%\", (${total_failed}/${total_attempts})*100}")"
    read -p "按任意键继续..."
}

function backup_ssh_config() {
    backup_dir="/backup/ssh"
    mkdir -p ${backup_dir}
    cp /etc/ssh/sshd_config ${backup_dir}/sshd_config_$(date +%F_%H-%M-%S)
    echo "SSH 配置文件已备份到 ${backup_dir}"
    read -p "按任意键继续..."
}

function check_cron_jobs() {
    cron_jobs=$(crontab -l 2>/dev/null)
    
    if [ -z "$cron_jobs" ]; then
        echo "无定时任务"
    else
    	echo "当前机台的定时任务:"
        echo "$cron_jobs"
    fi
    read -p "按任意键继续..."
}

function external_connection_geo() {
    echo "外部连接 IP 统计及地理位置信息："
    netstat -ntu | awk '{print $5}' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -Ev '^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\.|^112\.1\.72\.21$' | sort | uniq -c | sort -nr | while read count ip; do
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            geo_info=$(curl -s "https://ipinfo.io/${ip}/json")
            city=$(echo "$geo_info" | grep '"city"' | awk -F '"' '{print $4}')
            region=$(echo "$geo_info" | grep '"region"' | awk -F '"' '{print $4}')
            country=$(echo "$geo_info" | grep '"country"' | awk -F '"' '{print $4}')
            org=$(echo "$geo_info" | grep '"org"' | awk -F '"' '{print $4}')
            echo "连接数: $count | IP: $ip | 地理位置: ${city}, ${region}, ${country} | 组织: ${org}"
        fi
    done
    read -p "按任意键继续..."
}




while true; do
    log_num=$(wc -l < /var/log/auth.log)
    verification_failed=$(grep "Failed password" /var/log/auth.log | wc -l)

    clear
    echo ""
    echo "+-----------------------------------------------------------------------------------------------------+"
    echo "| 此脚本可以分析Ubuntu系统auth.log日志检查本机是否被ssh暴力破解，并提供一些安全防护措施               |"
    echo "+-----------------------------------------------------------------------------------------------------+"
    echo ""
    echo "当前日志条数: ${log_num}"
    echo "当前验证失败次数: ${verification_failed}"
    echo ""
    echo "> 菜单 <"
    echo ""
    echo "[0] 退出脚本"
    echo "---"
    echo "[1] 登录失败的 IP（前 10 个）"
    echo "[2] 登录失败的用户（前 10 个）"
    echo "[3] 登录失败时间段分析"
    echo "---"
    echo "[4] 登录成功的 IP（前 10 个）"
    echo "[5] 登录成功的用户（前 10 个）"
    echo "---"
    echo "[6] 选择封禁恶意 IP"
    echo "[7] 解封被封禁的 IP"
    echo "---"
    echo "[8] 查看当前 SSH 配置信息"
    echo "[9] 登录统计概览"
    echo "[10] 查看机台定时任务"
    echo "[11] 查看ip地理位置"
    echo "---"
    echo "[12] 备份 SSH 配置文件"
    echo "[13] 重启 SSH 服务"
    echo ""

    read -p "请输入序号: " num

    case ${num} in
        0) exit ;;
        1) failed_ips ;;
        2) failed_users ;;
        3) failed_time_analysis ;;
        4) successful_ips ;;
        5) successful_users ;;
        6) block_malicious_ips ;;
        7) unblock_ip ;;
        8) view_ssh_config ;;
        9) login_summary ;;
        10) check_cron_jobs ;;
        11) external_connection_geo ;;
        12) backup_ssh_config ;;
        13) systemctl restart sshd && echo "SSH 服务已重启！" && read -p "按任意键继续..." ;;
        *) echo "无效输入，请重新输入！" ;;
    esac
done



