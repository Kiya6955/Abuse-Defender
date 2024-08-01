#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    clear
    echo "You should run this script with root!"
    echo "Use sudo -i to change user to root"
    exit 1
fi

function main_menu {
    clear
    echo "----------- Abuse Defender -----------"
    echo "https://github.com/Kiya6955/Abuse-Defender"
    echo "--------------------------------------"
    echo "Choose an option:"
    echo "1-Block Abuse IP-Ranges"
    echo "2-Whitelist an IP/IP-Ranges manually"
    echo "3-Block an IP/IP-Ranges manually"
    echo "4-View Rules"
    echo "5-Clear all rules"
    echo "6-Exit"
    read -p "Enter your choice: " choice
    case $choice in
    1) block_ips ;;
    2) whitelist_ips ;;
    3) block_custom_ips ;;
    4) view_rules ;;
    5) clear_chain ;;
    6) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option"; main_menu ;;
    esac
}

function block_ips {
    clear
    if ! command -v iptables &> /dev/null; then
        apt-get update
        apt-get install -y iptables
    fi
    if ! dpkg -s iptables-persistent &> /dev/null; then
        apt-get update
        apt-get install -y iptables-persistent
    fi

    if ! iptables -L abuse-defender -n >/dev/null 2>&1; then
        iptables -N abuse-defender
    fi

    if ! iptables -L OUTPUT -n | grep -q "abuse-defender"; then
        iptables -I OUTPUT -j abuse-defender
    fi

    clear
    read -p "Are you sure about blocking abuse IP-Ranges? [Y/N] : " confirm

    if [[ $confirm == [Yy]* ]]; then
        clear
        read -p "Do you want to delete the previous rules? [Y/N] : " clear_rules
        if [[ $clear_rules == [Yy]* ]]; then
            iptables -F abuse-defender
        fi

        IP_LIST=$(curl -s 'https://raw.githubusercontent.com/Kiya6955/Abuse-Defender/main/abuse-ips.ipv4')

        if [ $? -ne 0 ]; then
            echo "Failed to fetch the IP-Ranges list. Please contact @Kiya6955"
            read -p "Press enter to return to Menu" dummy
            main_menu
        fi

        for IP in $IP_LIST; do
            iptables -A abuse-defender -d $IP -j DROP
        done

        iptables-save > /etc/iptables/rules.v4

        clear
        echo "Abuse IP-Ranges blocked successfully."
        read -p "Press enter to return to Menu" dummy
        main_menu
    else
        echo "Cancelled."
        read -p "Press enter to return to Menu" dummy
        main_menu
    fi
}

function whitelist_ips {
    clear
    echo "Enter IP-Ranges to whitelist (like 192.168.1.0/24):"
    read ip_range

    iptables -I abuse-defender -s $ip_range -j ACCEPT

    iptables-save > /etc/iptables/rules.v4

    clear
    echo "$ip_range whitelisted successfully."
    read -p "Press enter to return to Menu" dummy
    main_menu
}

function block_custom_ips {
    clear
    echo "Enter IP-Ranges to block (like 192.168.1.0/24):"
    read ip_range

    iptables -A abuse-defender -d $ip_range -j DROP

    iptables-save > /etc/iptables/rules.v4

    clear
    echo "$ip_range blocked successfully."
    read -p "Press enter to return to Menu" dummy
    main_menu
}

function view_rules {
    clear
    iptables -L abuse-defender -n
    echo "Press Enter to return to Menu"
    read -r dummy
    main_menu
}

function clear_chain {
    clear
    iptables -F abuse-defender
    iptables-save > /etc/iptables/rules.v4

    clear
    echo "All Rules cleared successfully."
    read -p "Press enter to return to Menu" dummy
    main_menu
}

main_menu
