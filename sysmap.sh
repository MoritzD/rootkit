#! /bin/bash
echo "reading file"
	# ensure a sysmap file was specifyed
if [  $# -eq 0 ]
	then
	echo "Plese specify sysmap file"
	exit 0
fi
	# set include guards (may not be necessary, but good to have)
echo "#ifndef SYSMAP_H" > sysmap.h
echo "#define SYSMAP_H" >> sysmap.h
echo "" >> sysmap.h

	# read line by line
while read line; do
	echo $line | grep -q ' D \| R \| T \|packet_rcv\|free_module'
		# found interesting line
	if [ $? == 0 ]; then 
		IFS=' ' read -ra INTR <<< "$line"
			# total string
		echo "${INTR[@]}"	
		echo -n "#define " >> sysmap.h
			# symbol_name
		echo -n "MAP_${INTR[2]} " >> sysmap.h
			# address
		echo "0x${INTR[0]}" >> sysmap.h
	fi
done <$1
echo "" >> sysmap.h
echo "#endif" >> sysmap.h
