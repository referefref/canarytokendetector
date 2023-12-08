#!/bin/zsh

RED="31"; GREEN="32"; BOLDGREEN="\e[1;${GREEN}m"; BOLDRED="\e[1;${RED}m"; ITALICRED="\e[3;${RED}m"; ENDCOLOR="\e[0m"

OPTIND=1

verbose=0;test_only=0;directory=0;recursive=0;location="";candidatesTested=0;totalCanaries=0;wordCanaries=0; excelCanaries=0; wireguardCanaries=0; sensitiveCommandCanaries=0; winFolderCanaries=0; MySQLCanaries=0;PDFCanaries=0;AzureCertCanaries=0;KubeconfigCanaries=0;CustomExeCanaries=0

echo -e "\n${BOLDGREEN}CanaryTokenDetector Version 1.0${ENDCOLOR}\n${BOLDRED}James Brine${ENDCOLOR} : ${ITALICRED}https://github.com/referefref/canarytokendetector${ENDCOLOR}"

show_help () { 
	echo -e "Released under GPL-3.0 license\nDecription: Tool that allows for the location and nullification of some types of canary tokens.\n" && echo -e "${BOLDRED}Currently Supported Canary Tokens:${ENDCOLOR}" && echo -e "Type|Detect|Nullify\n------------------------------|-------|--------\nMicrosoft Word|✓|✓\nMicrosoft Excel|✓|✓\nWireguard VPN Config|✓|✓\nSensitive Command Token|✓|✓\nWindows Folder|✓|✓\nMySQL Dump|✓|✓\nPDF Token|✓|✓\nAzure Login Certificate|✓|✓\nKubeconfig Token|✓|✓\nCustom Executable (.exe, .dll)|✓|✓\n" | column -t -s"|" && echo -e "\n\n${BOLDRED}Arguments and Options:${ENDCOLOR}" && echo -e "Flag|Option|Description|Argument|Default Value\n----|---------------|-------------------------------------------------|-------------------------|--------------\n-h|help|Show this dialogue\n-v|verbose|Verbose output| |False\n-t|test-mode|Check for presence only, do not nullify tokens| |True\n-d|directory|Check entire directory contents| |False\n-r|recursive|Scan recursively from directory or current path|Directory|False\n-f|location|File or Folder location|Path to file or folder|Current folder\n-o|output_file|Report output file|Path to file or folder|None" | column -t -s"|" && echo -e "\n"
}

while getopts "f:o:h?vtdr" opt
do
	case "$opt" in
		f) location=$OPTARG
			;;
		o) output_file=$OPTARG
			;;
		h|\?)
			show_help
			exit 0
			;;
		v) verbose=1
			;;
		t) test_only=1
			if [[ $verbose == "1" ]]; then echo "Running in test only mode"; fi
			;;
		d) directory=1
			if [[ $verbose == "1" ]]; then echo "Running in directory mode"; fi
			;;
		r) recursive=1
			if [[ $verbose == "1" ]]; then echo "Running in recursive mode"; fi
			;;
	esac
done

if [[ "$test_only" == "0" ]]; then echo -e "${BOLDRED}RUNNNING IN NULLIFY MODE... MAKE SURE DATA IS BACKED UP BEFORE PROCEEDING${ENDCOLOR}"; sleep 5; fi

shift $((OPTIND-1))
[ "${1:-}" = "--" ] && shift

find_files () {
	startTime=$(date +%s)
	if recursive=1; then maxDepth="999"; else maxDepth="1"; fi
	if [[ $directory == "1" ]]
	then
		if [[ $verbose == "1" ]]
		then
			echo "Searching $location for potential canary files"
			find "${location}" -maxdepth $maxDepth -type f \( -iname \*.docx -o -iname \*.xlsx -o -iname \*.exe -o -iname \*.dll -o -iname \*.conf -o -iname \*config -o -iname \*.pdf -o -iname \*.sql -o -iname \*.mysql -o -iname \*.azure -o -iname \*.pem -o -iname \*.reg -o -iname \*.ini -o -iname \*.config \) > candidates
			countOfCandidates=$(wc -l candidates | awk '{print $1}')
			echo "Discovered $countOfCandidates potential canary tokens..."
			cat candidates
		else
			find "${location}" -maxdepth $maxDepth -type f \( -iname \*.docx -o -iname \*.xlsx -o -iname \*.exe -o -iname \*.dll -o -iname \*.conf -o -iname \*config -o -iname \*.pdf -o -iname \*.sql -o -iname \*.mysql -o -iname \*.azure -o -iname \*.pem -o -iname \*.reg -o -iname \*.ini -o -iname \*.config \) > candidates
		fi
	else
		if [[ $verbose == "1" ]]
		then
			echo "Setting target file as $location"
		fi
		echo $location > candidates
	fi
}

discovery_loop () {
	while read candidate;
	do
		((candidatesTested++))
		if [[ "$candidate" == *".docx" || "$candidate" == *".xlsx" ]]
		then
			ms_office
		elif [[ "$candidate" == *".config" || "$candidate" == *"config" ]]
		then
			if grep -q "PersistentKeepalive" $candidate
			then
				wireguard_vpn_config
			else
				kubecfg_token
			fi
		elif [[ "$candidate" == *".ini" ]]
		then
			windows_folder_token
		elif [[ "$candidate" == *".mysql" || "$candidate" == *".sql" ]]
		then
			mysql_dump
		elif [[ "$candidate" == *".exe" || "$candidate" == *".dll" ]]
		then
			windows_binary
		elif [[ "$candidate" == *".pem" || "$candidate" == *".azure" ]]
		then
			azure_certificate
		elif [[ "$candidate" == *".pdf" ]]
		then
			PDF_check
		elif [[ "$candidate" == *".reg" ]]
		then
			sensitive_command
		fi
	done < candidates
	endTime=$(date +%s)
}

ms_office () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; echo "Extracting file..."; fi
	mkdir tmp
	mv $candidate tmp/$candidate
	unzip -q tmp/$candidate -d tmp/
	if grep -qR "canarytokens.com" tmp/.
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		if [[ "$candidate" == *"docx" ]]; then ((wordCanaries++)); echo $candidate >> wordCanaries.list; else ((excelCanaries++)); echo $candidate >> excelCanaries.list; fi
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			grep -lr "canarytokens.com" tmp | sed 's:/:\\\/:g' > files
			while read file;
			do
				# Added empty string prior to string to avoid MacOS errors
				sed -i '' 's/canarytokens.com//g' "$file"
			done < files
			rm files
			if [[ $verbose == "1" ]]; then echo "Compressing files..."; fi
			zip -q ../$candidate.tmp -r tmp/.
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv ../$candidate.tmp $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		else
			mv tmp/$candidate $candidate
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
		mv tmp/$candidate $candidate
	fi

	rm -Rf tmp
}

wireguard_vpn_config() {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	cp $candidate tmp/$candidate
	if grep -qR "52.18.63.80:51820" tmp/$candidate
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((wireguardCanaries++))
		echo $candidate >> wireguardCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			sed -i '' 's/52.18.63.80:51820//g' "tmp/$candidate"
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv tmp/$candidate $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp

}


sensitive_command () {
# Requires a .reg file
# Nullify will break ALL sensitive command canary tokens, and maybe some other stuff...

	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	if grep -qR "*CMD*canarytokens.com" $candidate
	then
		mkdir tmp
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((sensitiveCommandCanaries++))
		echo $candidate >> sensitiveCommandCanaries.list
		cp "$candidate" "tmp/$candidate"
		sensCandidateCount=$(grep "*CMD*canarytokens.com" $candidate | wc -l | awk '{print $1}')
		sensitiveCommandCanaries=$(echo "$sensitiveCommandCanaries + $sensCandidateCount" | bc)
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			# This is enough to break the DNS Resolution hidden command for all instances of hidden command canary tokens
			sed -i '' 's/canarytokens.com//g' "tmp/$candidate"
			cp "tmp/$candidate" "$candidate"
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp

}

windows_folder_token () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	cp $candidate tmp/$candidate
	if grep -qR "canarytokens.com\\resource.dll" tmp/$candidate
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((winFolderCanaries++))
		echo $candidate >> winFolderCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			sed -i '' 's/canarytokens.com\\resource.dll//g' "tmp/$candidate"
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv tmp/$candidate $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi

	rm -Rf tmp
}

mysql_dump () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	cp $candidate tmp/$candidate
	if grep -qR "YW5hcnl0b2tlbnMuY29t" tmp/$candidate
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((MySQLCanaries++))
		echo $candidate >> MySQLCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			sed -i '' 's/YW5hcnl0b2tlbnMuY29t//g' "tmp/$candidate"
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv tmp/$candidate $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi

	rm -Rf tmp

}

PDF_check () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	cp $candidate tmp/$candidate
	if [[ $verbose == "1" ]]; then echo "Unpacking PDF"; fi
	# In non-java environments, qpdf can be used to unpack and repack the PDF
	#qpdf --qdf tmp/$candidate tmp/unpacked.pdf
	pdftk $candidate output tmp/unpacked.pdf uncompress
	if grep -qR "canarytoken" tmp/unpacked.pdf
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((PDFCanaries++))
		echo $candidate >> PDFCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			# A better approach here would be to select the objectstr from the PDF and remove it, however the below seems to work without damaging the contents
			endpoint=$(grep "canarytokens.net" tmp/unpacked.pdf | awk -F'(' '{print $2}' | sed 's/)//g')
			escapedEndpoint=$(echo $endpoint | sed -e 's#\/#\\/#g')
			# MacOS doesn't like in-place edit with non UTF-8 chars
			cat tmp/unpacked.pdf | LC_ALL=C sed -e "s#${escapedEndpoint}##g" > tmp/unpackedEdit.pdf
			# If the above doesn't work in linux: sed -i "s#${escapedEndpoint}##g" "tmp/unpacked.pdf"
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv tmp/unpackedEdit.pdf $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp

}

azure_certificate () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	cp $candidate tmp/$candidate
	if grep -qR "59c2944e-c983-4cb6-bc4a-96b9b2b58e3a" tmp/$candidate
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((AzureCertCanaries++))
		echo $candidate >> AzureCertCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			sed -i '' 's/59c2944e-c983-4cb6-bc4a-96b9b2b58e3a//g' "tmp/$candidate"
			if [[ $verbose == "1" ]]; then echo "Replacing original file"; fi
			mv tmp/$candidate $candidate
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp

}

kubecfg_token () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	if grep -qR "52.18.63.80:6443" $candidate
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((KubeconfigCanaries++))
		echo $candidate >> KubeconfigCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			sed -i '' 's/52.18.63.80:6443//g' "tmp/$candidate"
			cp "tmp/$candidate" "$candidate"
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp
}

windows_binary () {
	if [[ $verbose == "1" ]]; then echo "Checking if canary token is present in $candidate"; fi
	mkdir tmp
	strings $candidate > stringsTmp
	if grep -qR "canarytokens.net/any_path" stringsTmp
	then
		echo -e "${BOLDRED}Canary token detected in file:${ENDCOLOR} $candidate"
		((CustomExeCanaries++))
		echo $candidate >> CustomExeCanaries.list
		if [[ $test_only == "0" ]]
		then 
			if [[ $verbose == "1" ]]; then echo "Removing token..."; fi
			python3 disitool.py delete "$candidate" "$candidate.tmp"
			cp "$candidate.tmp" "$candidate"
			if [[ $verbose == "1" ]]; then echo "Done"; fi
		fi
	else
		if [[ $verbose == "1" ]]; then echo "${BOLDGREEN}No canary token detected${ENDCOLOR}"; fi
	fi
	rm -Rf tmp
}

generate_report () {
	totalTime=$(echo "${endTime} - ${startTime}" | bc)
	if [[ $verbose == "1" ]]; then echo "Generating Report"; echo "Total Time Elapsed: $totalTime"; fi

	today=$(date "+%Y-%m-%d")
	echo "Canary Token Scan for $location on $today" >> $output_file
	echo "-----------------------------------------" >> $output_file
	echo "Time Taken: $totalTime seconds" >> $output_file
	echo "Scan Target: $location" >> $output_file
	if [[ "$test_only" == "0" ]]; then echo "Mode: NULLIFY" >> $output_file; else echo "Mode: Test Only" >> $output_file; fi
	echo "Candidates Tested: $candidatesTested" >> $output_file
	totalDetections=$(echo "$wordCanaries + $excelCanaries + $wireguardCanaries + $sensitiveCommandCanaries + $winFolderCanaries + $MySQLCanaries + $PDFCanaries + $AzureCertCanaries + $KubeconfigCanaries + $CustomExeCanaries" | bc)
	echo "Total Canaries Detected: $totalDetections" >> $output_file
	if [[ "$wordCanaries" != "0" ]]
	then
		echo "Microsoft Word Canaries: $wordCanaries" >> $output_file
		cat wordCanaries.list >> $output_file
		rm wordCanaries.list
	fi
	if [[ "$excelCanaries" != "0" ]]
	then
		echo "Microsoft Excel Canaries: $excelCanaries" >> $output_file
		cat excelCanaries.list >> $output_file
		rm excelCanaries.list
	fi
	if [[ "$wireguardCanaries" != "0" ]]
	then 
		echo "Wireguard VPN Canaries: $wireguardCanaries" >> $output_file
		cat wireguardCanaries.list >> $output_file
		rm wireguardCanaries.list
	fi
	if [[ "$sensitiveCommandCanaries" != "0" ]]
	then
		echo "Microsoft Windows Sensitive Command Canaries: $sensitiveCommandCanaries" >> $output_file
		cat sensitiveCommandCanaries.list >> $output_file
		rm sensitiveCommandCanaries.list
	fi
	if [[ "$winFolderCanaries" != "0" ]]
	then
		echo "Microsoft Windows Folder Canaries: $winFolderCanaries" >> $output_file
		cat winFolderCanaries.list >> $output_file
		rm winFolderCanaries.list
	fi
	if [[ "$MySQLCanaries" != "0" ]]
	then
		echo "MySQL Dump Canaries: $MySQLCanaries" >> $output_file
		cat MySQLCanaries.list >> $output_file
		rm MySQLCanaries.list
	fi
	if [[ "$PDFCanaries" != "0" ]]
	then
		echo "PDF Token Canaries: $PDFCanaries" >> $output_file
		cat PDFCanaries.list >> $output_file
		rm PDFCanaries.list
	fi
	if [[ "$AzureCertCanaries" != "0" ]]
	then
		echo "Microsoft Azure Login Certificate Canaries: $AzureCertCanaries" >> $output_file
		cat AzureCertCanaries.list >> $output_file
		rm AzureCertCanaries.list
	fi
	if [[ "$KubeconfigCanaries" != "0" ]]
	then
		echo "Kubeconfig Canaries: $KubeconfigCanaries" >> $output_file
		cat KubeconfigCanaries.list >> $output_file
		rm KubeConfigCanaries.list
	fi
	if [[ "$CustomExeCanaries" != "0" ]]
	then
		echo "Custom Windows Executable Canaries: $CustomExeCanaries" >> $output_file
		cat CustomExeCanaries.list >> $output_file
		rm CustomExeCanaries.list
	fi

	echo -e "${BOLDGREEN}Report exported to $output_file${ENDCOLOR}"
}

find_files
discovery_loop
if [[ ! -z "$output_file" ]]; then generate_report; fi
