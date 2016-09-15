#!/usr/bin/env ruby
# coding: utf-8
require 'optparse'
require 'json'
require 'csv'
require 'set'
require 'nokogiri'
require 'net/https'
require 'erb'

require 'pry'

class JIRAUpdate

  def initialize()
    @jira_host = ENV['JIRA_URI']
    @jira_port = 443
    @use_ssl = true
  end

  def run_from_options(argv)
    parse_options(argv)

    if @options[:type]
      get_score(@options)
    elsif@options[:jira_search]
      get_findings(@options)
    else
      # do nothing
    end
  end

  def parse_options(argv)
    argv[0] = '--help' unless argv[0]
    @options = {}
    OptionParser.new do |opts|
      opts.banner = <<-USAGE
Usage:
  #{__FILE__} [options]

Examples:

  Find JIRA issue by key and display
    #{__FILE__} -d directory -t nessus

Options:
      USAGE
      opts.on('-d', '--directory DIRNAME', 'Directory to look for files in') do |p|
        @options[:directory] = p
      end
      opts.on('-t', '--scan_type TYPE', 'Type of scan so parse (nessus, acunetix, appdetectivepro') do |p|
        @options[:type] = p
      end
      opts.on('-j', '--jira_search JQL', 'Search JIRA with JQL, return results') do |p|
        @options[:jira_search] = p
      end
      opts.on('-v', '--verbose', 'Show things like risk level in the output') do |p|
        @options[:verbose] = p
      end
    end.parse!(argv)
  end

  # for a directory tree containing scan results by month and type, get all of the scores
  # scan_results/
  # ├── 2016.01
  # │   ├── acunetix
  # │   ├── appdetectivepro
  # │   └── nessus
  # ├── 2016.02
  # │   ├── acunetix
  # │   ├── appdetectivepro
  # │   └── nessus
  def get_score(options)

    # storage for all the monthly results
    all_results = {}
    
    Dir.foreach(options[:directory]) do |month|
      next if month == '.' or month == '..' or month !~ /\d{4,4}\.\d{2,2}/

      if File.directory?(options[:directory] + '/' + month)
        month_results = get_month_detail(options, month)
        all_results[month] = month_results
      end
      
    end

    # collate and output total score by month
    totals = compute_score(all_results)

    puts JSON.pretty_generate(totals)
    
  end

  # calc a score per month
  # month =>
  #   total    = total unique findings currently found
  #   existing = findings that were not fixed from last month
  #   new      = new findings that were not in previous month
  #   closed   = findings closed since last month
  #
  # total    = cur_month.ids.count
  # existing = intersection of cur_month.ids and prev_month.ids
  # new      = cur_month.total - cur_month.existing
  # closed   = prev_month.total - cur_month.existing
  def compute_score(results)
    # results is a hash of months and the results for each month
    # month => type => id => detail

    totals = { }
    prev_month_result = { }
    prev_month_totals = { }
    
    # iterate through each month
    results.sort.each do | month, result |      
      month_total = compute_month_totals(result)
      totals[month] = month_total
      # total is already given by month_total["total"]
      totals[month]["existing"] = compute_intersection(prev_month_result, result)
      totals[month]["new"] = totals[month]["total"] - totals[month]["existing"]
      totals[month]["closed"] = prev_month_totals["total"] - totals[month]["existing"] if prev_month_totals.key?("total")

      prev_month_totals = totals[month]
      prev_month_result = result
    end

    return totals
                          
  end

  # what is the number of unique scan findings that exist in both months?
  def compute_intersection(prev_month, cur_month)

    intersection = 0
    
    cur_month.each do | type, findings |
      findings.each do | id, detail |
        if prev_month.key?(type) && prev_month[type].key?(id) && detail["risk"] != "none" && detail["risk"] != "info"
          intersection += 1
          #puts "intersected: #{id} :: #{detail["risk"]}"
        else
          #puts "new: #{id} :: #{detail["risk"]}"
        end
      end
    end

    return intersection
  end
  
  # parse all of the raw scan results for a month
  def get_month_detail(options, month)

    nessus_results = {}
    acunetix_results = {}
    appdetectivepro_results= {}

    dir = @options[:directory] + '/' + month
    
    Dir.foreach(dir) do |file|
      next if file == '.' or file == '..'

      if File.directory?(dir + '/' + file)
        if file == "nessus"
          results = parse_nessus_files(dir + '/' + file, nessus_results)
        elsif file == "acunetix"
          results = parse_acunetix_files(dir + '/' + file, acunetix_results)
        elsif file == "appdetectivepro"
          results = parse_appdetectivepro_files(dir + '/' + file, appdetectivepro_results)
        end
      end
    end

    month_detail =
      {
        "nessus" => nessus_results,
        "acunetix" => acunetix_results,
        "appdetectivepro" => appdetectivepro_results,
      }

    return month_detail
    
  end
  
  # return a total number of unique findings by risk_level and total (unique findings and total hosts per finding)
  def compute_month_totals(month_detail)

    score = {}
    totals = { "total" => 0, "new" => 0, "existing" => 0, "closed" => 0 }
    if(@options[:verbose])
      totals["risk_level"] = {}
    end

    score = process_result(month_detail["acunetix"], "acunetix", score)
    score = process_result(month_detail["appdetectivepro"], "appdetectivepro", score)
    score = process_result(month_detail["nessus"], "nessus", score)

    score.each do |type, values|
      values.each do |risk, values|
        if(@options[:verbose])
          if !totals["risk_level"][risk]
            totals["risk_level"][risk] = {}
            totals["risk_level"][risk]["findings"] = 0
            totals["risk_level"][risk]["host_count"] = 0
          end
          
          totals["risk_level"][risk]["findings"] += values["findings"].to_i
          totals["risk_level"][risk]["host_count"] += values["host_count"].to_i
        end
        # add the number of findings up into a total for the month, only if they are 
        totals["total"] += values["findings"].to_i if(risk != "none" && risk != "info")
      end
    end
    
    return totals    
  end

  # compile a detail result for a type of scan into totals, unique findings and total hosts per finding
  def process_result(result, key, score)

    score[key] = {}

    result.each do |scan_id, results|

      # don't count informational messages
      if results["Risk"] != "info" && results["Risk"] != "none"

        if !score[key][results["risk"]]

          score[key][results["risk"]] = {}

          score[key][results["risk"]]["findings"] = 0
          score[key][results["risk"]]["host_count"] = 0
        end

        score[key][results["risk"]]["findings"] += 1
        score[key][results["risk"]]["host_count"] += results["hosts"].count
      end
    end

    return score
  end

  # nessus files are csv
  def parse_nessus_files(dir, results)
    
    Dir.glob(dir + '/' + '*.csv') do |file|
      results = parse_nessus_file(file, results)
    end

    return results
  end

  # acunetix files are xml :(
  def parse_acunetix_files(dir, results)

    Dir.glob(dir + '/' + '*.xml') do |file|
      results = parse_acunetix_file(file, results)
    end

    return results
  end

  # appdetectivepro files are xml :(
  def parse_appdetectivepro_files(dir, results)

    Dir.glob(dir + '/' + '*.xml') do |file|
      results = parse_appdetectivepro_file(file, results)
    end

    return results
  end

  # parse an individual appdetectivepro file
  # take the data and put it into a format that we can match with the
  # other scanner output types
  def parse_appdetectivepro_file(filename, results)

    doc = Nokogiri::XML(File.open(filename))

    report_items = doc.xpath('//CheckResults/CheckResult')
    report_items.each do |element|

      host = element.at_xpath('Asset').content
      name = element.at_xpath('CheckName').content
      risk = element.at_xpath('Risk').content
      description = element.at_xpath('Summary').content

      if !results[name]

        results[name] = {}
        results[name]["hosts"] = Set.new
        results[name]["description"] = description
        results[name]["risk"] = risk.downcase

      end

      results[name]["hosts"].add(host)

    end

    return results
  end


  # parse an individual acunetix file
  # take the data and put it into a format that we can match with the
  # other scanner output types
  def parse_acunetix_file(filename, results)

    doc = Nokogiri::XML(File.open(filename))

    report_items = doc.xpath('//ScanGroup/Scan/ReportItems/ReportItem')
    report_items.each do |element|

      host = doc.at_xpath('//StartURL').content
      name = element.at_xpath('Name').content
      risk = element.at_xpath('Severity').content
      description = element.at_xpath('Description').content

      if !results[name]

        results[name] = {}
        results[name]["hosts"] = Set.new
        results[name]["description"] = description
        results[name]["risk"] = risk

      end

      results[name]["hosts"].add(host)

    end

    return results
  end

  # parse an individual nessusfile
  # take the data and put it into a format that we can match with the
  # other scanner output types
  #
  # Nessus CSVs are like this:
  # Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output
  def parse_nessus_file(filename, results)

    CSV.foreach(filename, :headers => true) do |row|
      # we don't care about rows that have risk=none
      if row["Risk"] != "None"

        if !results[row["Plugin ID"]]
          results[row["Plugin ID"]] = {}
          results[row["Plugin ID"]]["hosts"] = Set.new # use a set so we can remove duplicate host entries
          results[row["Plugin ID"]]["description"] = row["Description"]
          results[row["Plugin ID"]]["plugin Output"] = row["Plugin Output"]
          results[row["Plugin ID"]]["risk"] = row["Risk"].downcase
          results[row["Plugin ID"]]["cve"] = row["CVE"]
          results[row["Plugin ID"]]["cvss"] = row["CVSS"]
        end

        results[row["Plugin ID"]]["hosts"].add(row["Host"])
      end
    end

    return results
  end

  # search for issues, return search results
  def search_jira(options)

    jira_issues = {}

    jql_encoded = ERB::Util.url_encode(options[:jira_search])

    http = Net::HTTP.new(@jira_host, @jira_port)
    http.use_ssl = @use_ssl
    http.start do |http|
      req = Net::HTTP::Get.new('/rest/api/2/search?jql=' + jql_encoded + "&maxResults=500")

      # we make an HTTP basic auth by passing the
      # username and password
      req.basic_auth ENV['JIRA_USER'], ENV['JIRA_PASS']
      resp, data = http.request(req)

      if resp.code.eql? '200'
        #print "Data: " +  JSON.pretty_generate(JSON.parse(resp.body.to_s))
        jira_issues = JSON.parse(resp.body.to_s)
      else
        puts "Error: " + resp.code.to_s + "\n" + resp.body
      end
    end

    return jira_issues
  end

  def get_findings(options)

    issues = search_jira(options)

    parsed_issues = {}

    issues["issues"].each do | issue |

      puts "Key: #{issue["key"]}"
      puts "Summary: #{issue["fields"]["summary"]}"
      puts "Source: #{issue["fields"]["customfield_12756"]["value"]}"
      puts "Source ID: #{issue["fields"]["customfield_12757"]}"
      puts "Assets: #{issue["fields"]["customfield_12758"]}"
      puts "Assets (additional): #{issue["fields"]["customfield_13850"]}"
      puts "Assets (current): #{issue["fields"]["customfield_14050"]}"

    end

  end

end

JIRAUpdate.new.run_from_options(ARGV) if __FILE__ == $PROGRAM_NAME
