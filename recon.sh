#!/bin/bash

range=$1

resolvers="/root/tools/dnsvalidator/resolvers.txt"

worlist="/root/tools/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt"

resolve_domain="massdns -r /root/tools/massdns/lists/resolvers.txt -t A -o S -w"


domain_enum(){


	for domain in $(cat $range);

	do

		mkdir -p $domain $domain/sources $domain/Recon/hidden_dir $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan $domain/Recon/vulnerabilities $domain/Recon/scree_shoort $domain/Recon/API_secret

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mSubfinder Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		subfinder -d $domain -t 100 -v -o $domain/sources/subfinder.txt 

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mAsset Finder Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mAmass Enum Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		amass enum -passive -d $domain -o $domain/sources/amass.txt

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mCrt.sh Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		crt.sh $domain > $domain/sources/crt.txt

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mShuffledns Is Starting...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		shuffledns -d $domain -w $worlist -r $resolvers -o $domain/sources/shuffledns.txt -wt 9000 -t 1000 
		
		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mKnockknock Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

	cd /root/tools/knock/knockpy/ &&  python3 knockpy.py $domain --no-http --no-local  -o /root/basic-recon/$domain/sources/


		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mSorting Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cd /root/basic-recon/$domain/sources/ && sort subfinder.txt assetfinder.txt amass.txt  crt.txt shuffledns.txt  | uniq -u >  /root/basic-recon/$domain/sources/all.txt &&  cd ../../ 

	done

}

domain_enum

resolving_domains(){

	for domain in $(cat $range);

	do

		printf "\n\n-------------------------------------------------------------\n"
		printf "          \e[33mBurp Forcing The Subdomain Is Starting...\e[0m                  "
		printf "\n---------------------------------------------------------------\n\n"

		shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers

	done

}

resolving_domains

http_prob(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mHTTPS Probe Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cat $domain/domains.txt | httpx -threads 300 -o $domain/Recon/url.txt

		cat $domain/domains.txt | httprobe -t 100 | tee $domain/Recon/all_url.txt

	done

}

http_prob

check_state(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mcheck_state...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

	cat $domain/domains.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t  Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk

done
}
check_state

scanner(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mNuclei Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/cves  -c 33 -o  $domain/Recon/nuclei/cves.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/default-logins/ -c 33 -o  $domain/Recon/nuclei/default-logins.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/dns/ -c 33 -o  $domain/Recon/nuclei/dns.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/exposed-panels/ -c 33 -o  $domain/Recon/nuclei/exposed-panels.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/exposures/ -c 33 -o  $domain/Recon/nuclei/exposures.txt
 
		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/network/ -c 33 -o  $domain/Recon/nuclei/network.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/takeovers/ -c 33 -o  $domain/Recon/nuclei/takeovers.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/technologies/ -c 33 -o  $domain/Recon/nuclei/technologies.txt

		cat $domain/Recon/url.txt | nuclei -t /root/tools/nuclei-templates/vulnerabilities/ -c 33 -o  $domain/Recon/nuclei/vulnerabilities.txt

	done
}

scanner
wayback_data(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mWaybackurl Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cat $domain/domains.txt | waybackurls | tee $domain/Recon/wayback/tmp.txt

		cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.svg|\.ttf|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/Recon/wayback/wayback.txt

		rm $domain/Recon/wayback/tmp.txt

	done

}

wayback_data

valid_urls(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mFuzzing Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		fuzzer -s -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -of csv -o $domain/Recon/wayback/valid-tmp.txt

		cat $domain/Recon/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/Recon/wayback/valid.txt

		rm $domain/Recon/wayback/valid-tmp.txt

	done

}

valid_urls

gf_patterns(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mGF Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"


		gf xss $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/xss.txt

		gf debug_logic $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/debug_logic.txt

		gf idor $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/idor.txt

		gf img-traversal $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/img-traversal.txt

		gf interestingEXT $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/interestingEXT.txt

		gf interestingparams $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/interestingparams.txt

		gf interestingsubs $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/interestingsubs.txt

		gf jsvar $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/jsvar.txt

		gf lfi $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/lfi.txt

		gf rce $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/rce.txt

		gf redirect $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/redirect.txt

		gf sqli $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/sqli.txt

		gf ssrf $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/ssrf.txt

		gf aws-keys_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/aws-keys_secrets.txt

		gf aws-s3_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/aws-s3_secrets.txt

		gf aws-keys $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/aws-keys.txt

		gf asymmetric-keys_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/asymmetric-keys_secrets.txt

		gf github_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/github_secrets.txt

		gf firebase_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/firebase_secrets.txt

		gf s3-buckets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/s3-buckets.txt

		gf slack-token_secrets $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/slack-token_secrets.txt

		gf servers $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/servers.txt

		gf upload-fields $domain/Recon/wayback/valid.txt | tee  $domain/Recon/gf/upload-fields.txt

	done

}

gf_patterns

custom_worlis(){

	for domain in $(cat $range);

	do
		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mMAKING coustem wordlist  ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt 

		cat $domain/Recon/wayback/wayback.txt | unfurl -unique keys > $domain/Recon/wordlist/params.txt

	done


}

custom_worlis

get_ip(){

	for domain in $(cat $range);

	do
		printf "\n\n---------------------------------------------\n"
		printf "          \e[33m Starting get_ip ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		$resolve_domain $domain/Recon/masscan/results.txt $domain/domains.txt

		gf ip $domain/Recon/masscan/results.txt | sort -u > $domain/Recon/masscan/ip.txt
		

	done
}
get_ip
sub_domina-take(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mSubdomain takeovers Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		subzy -targets $domain/domains.txt | tee $domain/Recon/vulnerabilities/takeovers.txt

	done
}
sub_domina-take

hidden(){

	for domain in $(cat $range);

	do
		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mDirsearch  Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"     

		cd /root/tools/dirsearch/

		python3 dirsearch.py -u $domain -t 80 -o $domain

		mv $domain /root/basic-recon/$domain/Recon/hidden_dir/

		cd /root/basic-recon/

	done
}
hidden

github_secrets(){

	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mGitdorking  Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cd /root/tools/git-hound

		git-hound --subdomain-file /root/basic-recon/$domain/domains.txt  /root/basic-recon/$domain/Recon/git-dorking/dorking.txt

		cd /root/basic-recon/

	done
}
github_secrets
API_secret(){

	for domain in $(cat $range);

	do

	    printf "\n\n---------------------------------------------\n"
		printf "          \e[33mAPI_secrets ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"

		cd  /root/basic-recon/$domain/Recon/API_secret

		cp /root/basic-recon/$domain/Recon/wayback/wayback.txt /root/basic-recon/$domain/Recon/API_secret/wayback.txt

		gau $domain -v -t 1000 -o $domain

		sort $domain wayback.txt | uniq -u >  uniq_files.txt

		cat uniq_files.txt | egrep -v "\.woff|\.svg|\.ttf|\.eot|\.png|\.jpeg|\.jpg|\.css|\.ico" >> wayback_only_html.txt

		cat uniq_files.txt  | grep “\.js” | uniq | sort >> wayback_js_files.txt

		cat uniq_files.txt  | grep “\.json” | uniq | sort >> wayback_json_files.txt

		grep -i -E "admin|auth|api|jenkins|corp|dev|stag|stg|prod|sandbox|swagger|aws|azure|uat|test|vpn|cms" wayback_only_html.txt >> important_http_urls.txt

		grep -i -E  "aws|s3" uniq_files.txt >> aws_s3_files.txt

		cat wayback_only_html.txt 

		cd /root/basic-recon/

	done
}
API_secret
find_xss(){


	for domain in $(cat $range);

	do

		printf "\n\n---------------------------------------------\n"
		printf "          \e[33mXSS find_xss Is Starting ...\e[0m                  "
		printf "\n---------------------------------------------\n\n"


		cat $domain/Recon/url.txt |  dalfox pipe --skip-bav | tee $domain/Recon/Recon/vulnerabilities/dalfox_xss.txt  

	done

}
find_xss
