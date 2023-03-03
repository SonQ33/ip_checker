$lst = Get-Content .\IP.txt

$for_rep = @()
$for_rep+="IP,Total Reports,VT Malicious,Domain Zone, Country Code"

foreach ($domain in $lst)
{
    $cur_str=""
    $cur_str+="$domain,"

    $apikey_abuse = "" #API Key here
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("Key", "$apikey_abuse")
    $body=@{}
    $body.Add("ipAddress", "$domain")
    $body.Add("maxAgeInDays", "90")
    $response = Invoke-WebRequest -Uri "https://api.abuseipdb.com/api/v2/check" -Method GET -Headers $headers -Body $body
    $report = $response.Content
    $report = $report.Split("{")[2]
    $report = $report.Split("}")[0]
    $report = $report.Split(",")

    foreach($current in $report)
    {
        if($current.Contains('Reports'))
        {
            $buffer = $current.Split(':')[1]
            $cur_str+="$buffer,"
        }
    }
    $apikey ="" #API Key here

    $domain = $domain
    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-apikey", "$apikey")
    $response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/$domain" -Method GET -Headers $headers

    $convert_resp = $response | ConvertFrom-Json
    $analys_result = $convert_resp.data.attributes.last_analysis_results
    $check = $analys_result |ConvertTo-Csv
    $split_detect = $check[2]
    $split_detect = $split_detect.Split(',')


    $numberClean = 0
    $numberUnrate = 0
    $numberMali = 0

    foreach($current in $split_detect)
    {
        if($current.Contains('clean'))
        {
            $numberClean+=1
        }
        elseif($current.Contains('unrated'))
        {
            $numberUnrate+=1
        }
        else
        {
            $numberMali+=1
        }

    }

    $cur_str+="$numberMali,"
    $apikey_kasp = "" #API Key here

    $headers=@{}
    $headers.Add("Accept", "application/json")
    $headers.Add("x-api-key", "$apikey_kasp")
    $response = Invoke-WebRequest -Uri "https://opentip.kaspersky.com/api/v1/search/ip?request=$domain" -Method GET -Headers $headers
    $report = $response.Content |ConvertFrom-Json
    $country_code = $report.IpGeneralInfo
    $country_code = $country_code.CountryCode
    $zone = $report.Zone

    $cur_str+="$zone,"
    $cur_str+="$country_code"

    $for_rep+=$cur_str
}

foreach($i in $for_rep)
{
    $i
}