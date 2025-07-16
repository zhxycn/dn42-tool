#!/bin/bash

# Get OS environment
OS=$(uname -s)
if [[ ${OS} != "Linux" ]]; then
    echo "This script only supports Linux."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_FAMILY="$ID"
else
    echo "Unable to determine OS family. Please ensure this script is run on a supported Linux distribution."
    exit 1
fi

ARCH=$(uname -m)

# Check running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must run as root."
    exit 1
fi

# DN42 Information Variables
DN42_ASN=""
DN42_IPV4_CIDR=""
DN42_IPV4=""
DN42_IPV6_CIDR=""
DN42_IPV6=""
WG_PUBLIC_KEY=""
WG_PRIVATE_KEY=""

get_dn42_info(){
    if [[ ! -f /etc/bird/bird.conf ]]; then
        return 1
    fi

    while IFS= read -r line; do
        case "$line" in
            "define OWNAS ="*)
                DN42_ASN=$(echo "$line" | awk -F'= ' '{print $2}' | tr -d ';')
                ;;
            "define OWNIP ="*)
                DN42_IPV4=$(echo "$line" | awk -F'= ' '{print $2}' | tr -d ';')
                ;;
            "define OWNNET ="*)
                DN42_IPV4_CIDR=$(echo "$line" | awk -F'= ' '{print $2}' | tr -d ';')
                ;;
            "define OWNIPv6 ="*)
                DN42_IPV6=$(echo "$line" | awk -F'= ' '{print $2}' | tr -d ';')
                ;;
            "define OWNNETv6 ="*)
                DN42_IPV6_CIDR=$(echo "$line" | awk -F'= ' '{print $2}' | tr -d ';')
                ;;
        esac
    done < <(grep -E '^define OWNAS =|^define OWNIP =|^define OWNNET =|^define OWNIPv6 =|^define OWNNETv6 =' /etc/bird/bird.conf)

    if [[ ! -f /etc/wireguard/privatekey || ! -f /etc/wireguard/publickey ]]; then
        return 1
    fi

    WG_PUBLIC_KEY=$(cat /etc/wireguard/publickey)
    WG_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
}

# Install packages
install(){
    case $OS_FAMILY in
        debian|ubuntu)
            apt update
            apt install -y $*
            ;;
        *)
            echo "Unsupported OS family: $OS_FAMILY"
            exit 1
            ;;
    esac
}

setup_dn42(){
    echo
    echo "Installing DN42 requirements..."
    if ! install bird2 wireguard; then
        echo "Failed to install requirements."
        exit 1
    fi

    echo
    echo "Downloading DN42 ROA configuration..."
    if ! command -v wget &> /dev/null; then
        echo "wget is not installed. Installing wget..."
        install wget
    fi
    wget -4 -O /etc/bird/dn42_roa.conf https://dn42.burble.com/roa/dn42_roa_bird2_4.conf
    wget -4 -O /etc/bird/dn42_roa_v6.conf https://dn42.burble.com/roa/dn42_roa_bird2_6.conf

    echo
    echo "Configuring BIRD..."

    while true; do
        read -rp "Please insert your DN42 ASN (e.g., 424242xxxx or AS424242xxxx): " DN42_ASN
        if [[ "$DN42_ASN" =~ ^(AS)?[1-9][0-9]{0,9}$ ]]; then
            DN42_ASN=${DN42_ASN#AS} # Remove AS prefix
            break
        else
            echo "Invalid ASN format. Please enter a valid ASN (e.g., 424242xxxx or AS424242xxxx)."
        fi
    done

    read -rp "Do you have a DN42 IPv4 CIDR? (Y/n)" has_ipv4
    if [[ -z "$has_ipv4" || "$has_ipv4" =~ ^[Yy]$ ]]; then
        while true; do
            read -rp "Please insert your DN42 IPv4 CIDR (e.g., 172.22.0.0/27): " DN42_IPV4_CIDR
            if [[ "$DN42_IPV4_CIDR" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$ ]]; then
                break
            else
                echo "Invalid IPv4 CIDR format. Please enter a valid IPv4 CIDR (e.g., 172.22.0.0/27)."
            fi
        done
        while true; do
            read -rp "Please insert your DN42 IPv4 address for this node (e.g., 172.22.0.1): " DN42_IPV4
            if [[ "$DN42_IPV4" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]]; then
                break
            else
                echo "Invalid IPv4 address format. Please enter a valid IPv4 address (e.g., 172.22.0.1)."
            fi
        done
        has_ipv4=true
    else
        has_ipv4=false
    fi

    read -rp "Do you have a DN42 IPv6 CIDR? (Y/n)" has_ipv6
    if [[ -z "$has_ipv6" || "$has_ipv6" =~ ^[Yy]$ ]]; then
        while true; do
            read -rp "Please insert your DN42 IPv6 CIDR (e.g., fd42:4242:xxxx::/48): " DN42_IPV6_CIDR
            if [[ "$DN42_IPV6_CIDR" =~ ^([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,7}|([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6})?::([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6})?)\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]; then
                break
            else
                echo "Invalid IPv6 CIDR format. Please enter a valid IPv6 CIDR (e.g., fd42:4242:xxxx::/48)."
            fi
        done
        while true; do
            read -rp "Please insert your DN42 IPv6 address for this node (e.g., fd42:4242:xxxx::1): " DN42_IPV6
            if [[ "$DN42_IPV6" =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$ ]]; then
                break
            else
                echo "Invalid IPv6 address format. Please enter a valid IPv6 address (e.g., fd42:4242:xxxx::1)."
            fi
        done
        has_ipv6=true
    else
        has_ipv6=false
    fi

    mkdir -p /etc/bird/peers

    mv /etc/bird/bird.conf /etc/bird/bird.conf.bak 2>/dev/null

    # BIRD config
    cat <<EOF > /etc/bird/bird.conf
define OWNAS = $DN42_ASN;
EOF

    if [[ "$has_ipv4" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf
define OWNIP = $DN42_IPV4;
define OWNNET = $DN42_IPV4_CIDR;
define OWNNETSET = [$DN42_IPV4_CIDR+];
EOF
    fi

    if [[ "$has_ipv6" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf
define OWNIPv6 = $DN42_IPV6;
define OWNNETv6 = $DN42_IPV6_CIDR;
define OWNNETSETv6 = [$DN42_IPV6_CIDR+];
EOF
    fi

    if [[ "$has_ipv4" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf

router id OWNIP;
EOF
    else
        router_id=$(printf "10.%d.%d.%d" $((DN42_ASN >> 16 & 255)) $((DN42_ASN >> 8 & 255)) $((DN42_ASN & 255)))
        cat <<EOF >> /etc/bird/bird.conf

router id $router_id;
EOF
    fi

    cat <<EOF >> /etc/bird/bird.conf

protocol device {
    scan time 10;
}
EOF

    if [[ "$has_ipv4" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf

function is_self_net() {
    return net ~ OWNNETSET;
}

function is_valid_network() {
    return net ~ [
        172.20.0.0/14{21,29}, # dn42
        172.20.0.0/24{28,32}, # dn42 Anycast
        172.21.0.0/24{28,32}, # dn42 Anycast
        172.22.0.0/24{28,32}, # dn42 Anycast
        172.23.0.0/24{28,32}, # dn42 Anycast
        172.31.0.0/16+,       # ChaosVPN
        10.100.0.0/14+,       # ChaosVPN
        10.127.0.0/16{16,32}, # neonetwork
        10.0.0.0/8{15,24}     # Freifunk.net
    ];
}

roa4 table dn42_roa;

protocol static {
    roa4 { table dn42_roa; };
    include "/etc/bird/dn42_roa.conf";
};

protocol kernel {
    scan time 20;

    ipv4 {
        import none;
        export filter {
            if source = RTS_STATIC then reject;
            krt_prefsrc = OWNIP;
            accept;
        };
    };
}

protocol static {
    route OWNNET reject;

    ipv4 {
        import all;
        export none;
    };
}
EOF
    fi

    if [[ "$has_ipv6" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf

function is_self_net_v6() {
    return net ~ OWNNETSETv6;
}

function is_valid_network_v6() {
  return net ~ [
    fd00::/8{44,64} # ULA address space as per RFC 4193
  ];
}

roa6 table dn42_roa_v6;

protocol static {
    roa6 { table dn42_roa_v6; };
    include "/etc/bird/dn42_roa_v6.conf";
};

protocol kernel {
    scan time 20;

    ipv6 {
        import none;
        export filter {
            if source = RTS_STATIC then reject;
            krt_prefsrc = OWNIPv6;
            accept;
        };
    };
};

protocol static {
    route OWNNETv6 reject;

    ipv6 {
        import all;
        export none;
    };
}
EOF
    fi

    cat <<EOF >> /etc/bird/bird.conf

template bgp dnpeers {
    local as OWNAS;
    path metric 1;
EOF

    if [[ "$has_ipv4" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf

    ipv4 {
        import filter {
            if is_valid_network() && !is_self_net() then {
                if (roa_check(dn42_roa, net, bgp_path.last) != ROA_VALID) then {
                    print "[dn42] ROA check failed for ", net, " ASN ", bgp_path.last;
                    reject;
                }
                accept;
            }
            reject;
        };

        export filter {
            if is_valid_network() && source ~ [RTS_STATIC, RTS_BGP] then accept;
            reject;
        };
        import limit 1000 action block;
    };
EOF
    fi

    if [[ "$has_ipv6" == true ]]; then
        cat <<EOF >> /etc/bird/bird.conf

    ipv6 {
        import filter {
            if is_valid_network_v6() && !is_self_net_v6() then {
                if (roa_check(dn42_roa_v6, net, bgp_path.last) != ROA_VALID) then {
                    print "[dn42] ROA check failed for ", net, " ASN ", bgp_path.last;
                    reject;
                }
                accept;
            }
            reject;
        };
        export filter {
            if is_valid_network_v6() && source ~ [RTS_STATIC, RTS_BGP] then accept;
            reject;
        };
        import limit 1000 action block;
    };
EOF
    fi

    cat <<EOF >> /etc/bird/bird.conf
}

include "/etc/bird/peers/*";
EOF

    birdc configure

    echo "BIRD configuration completed. You can find configuration in /etc/bird/bird.conf."

    echo
    echo "Generating WireGuard keys..."

    wg genkey | tee privatekey | wg pubkey > publickey

    mkdir -p /etc/wireguard
    cp privatekey publickey /etc/wireguard/

    echo
    echo "WireGuard keys generated:"
    echo "Private Key: $(cat privatekey)"
    echo "Public Key: $(cat publickey)"

    echo
    echo "Finished setting up DN42 environment."

    echo
    echo "Press any key to continue..."
    read -n 1 -s
}

show_dn42_info(){
    echo
    echo "Here is your DN42 information:"
    echo
    echo "AS: AS${DN42_ASN}"
    echo "IPv4 CIDR: ${DN42_IPV4_CIDR}"
    echo "IPv4: ${DN42_IPV4}"
    echo "IPv6 CIDR: ${DN42_IPV6_CIDR}"
    echo "IPv6: ${DN42_IPV6}"
    echo
    echo "Press any key to continue..."
    read -n 1 -s
}

get_dn42_info

# Main menu
while true; do
    clear

    echo """
    ____     _   __   __ __   ___          ______   ____    ____     __ 
   / __ \   / | / /  / // /  |__ \        /_  __/  / __ \  / __ \   / / 
  / / / /  /  |/ /  / // /_  __/ / ______  / /    / / / / / / / /  / /  
 / /_/ /  / /|  /  /__  __/ / __/ /_____/ / /    / /_/ / / /_/ /  / /___
/_____/  /_/ |_/     /_/   /____/        /_/     \____/  \____/  /_____/

"""

if [[ "$DN42_ASN" ]]; then
    echo "Welcome, AS${DN42_ASN}!"
fi

    echo """
1. Set up DN42 environment
2. Show DN42 information
3. Add a DN42 peer
4. Show DN42 peers
5. Remove a DN42 peer

0. Exit
"""

    read -rp "Please select an option: " option

    case $option in
        1)
            setup_dn42
            ;;
        2)
            show_dn42_info
            ;;
        3)
            ;;
        4)
            ;;
        5)
            ;;
        0)
            echo
            echo "Exiting..."
            break
            ;;
        *)
            echo
            echo "Invalid option. Please try again."
            ;;
    esac
done
