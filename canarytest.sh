#!/bin/zsh

echo "Checking if canary token is present in document" 
echo "Extracting file..."
mkdir tmp
mv $1 tmp/$1
unzip -q tmp/$1 -d tmp/
if grep -qR "canarytokens.com" tmp/.
then
	echo "Canary token detected"
	echo "Removing token..."
	grep -lr "canarytokens.com" tmp | sed 's:/:\\\/:g' > files
	while read file;
	do
		# Added empty string prior to string to avoid MacOS errors
		sed -i '' 's/canarytokens.com//g' "$file"
	done < files
	rm files
	echo "Compressing files..."
	zip -q ../$1.tmp -r tmp/.
	echo "Replacing original file"
	mv ../$1.tmp $1
	echo "Done"
else
	echo "No canary token detected :)"
fi

rm -Rf tmp
