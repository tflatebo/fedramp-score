#!/usr/bin/env ruby
require 'optparse'
require 'json'
require 'csv'
require 'set'
require 'nokogiri'

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
    end.parse!(argv)
  end

  # look in a directory for a list of files of a certain type
  def get_score(options)

    nessus_results = {}
    acunetix_results = {}
    appdetectivepro_results= {}

    Dir.foreach(@options[:directory]) do |file|
      next if file == '.' or file == '..'

      if File.directory?(@options[:directory] + '/' + file)
        if file == "nessus"
          results = parse_nessus_files(@options[:directory] + '/' + file, nessus_results)
        elsif file == "acunetix"
          results = parse_acunetix_files(@options[:directory] + '/' + file, acunetix_results)
        elsif file == "appdetectivepro"
          results = parse_appdetectivepro_files(@options[:directory] + '/' + file, appdetectivepro_results)
        end

      end

    end

    output_score(nessus_results, acunetix_results, appdetectivepro_results)
  end

  # print the score in a meaningful fashion
  def output_score(nessus, acunetix, appdetectivepro)

    score = {}
    totals = {}

    score = process_result(acunetix, "acunetix", score)
    score = process_result(appdetectivepro, "appdetectivepro", score)
    score = process_result(nessus, "nessus", score)

    score.each do |type, values|
      #binding.pry
      values.each do |risk, values|
      if !totals[risk]
        totals[risk] = {}
        totals[risk]["Findings"] = 0
        totals[risk]["Host Count"] = 0
      end

      #binding.pry
      totals[risk]["Findings"] += values["Findings"].to_i
      totals[risk]["Host Count"] += values["Host Count"].to_i
      end
    end

    puts JSON.pretty_generate(score)
    puts JSON.pretty_generate(totals)

  end

  def process_result(result, key, score)

    score[key] = {}

    result.each do |scan_id, results|

      # don't count informational messages
      if results["Risk"] != "info" && results["Risk"] != "none"

        if !score[key][results["Risk"]]

          score[key][results["Risk"]] = {}

          score[key][results["Risk"]]["Findings"] = 0
          score[key][results["Risk"]]["Host Count"] = 0

        end

        score[key][results["Risk"]]["Findings"] += 1
        score[key][results["Risk"]]["Host Count"] += results["Hosts"].count

      end


#      binding.pry
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

    #binding.pry
    doc = Nokogiri::XML(File.open(filename))
    #binding.pry

    report_items = doc.xpath('//CheckResults/CheckResult')
    report_items.each do |element|

      #binding.pry
      host = element.at_xpath('Asset').content
      name = element.at_xpath('CheckName').content
      risk = element.at_xpath('Risk').content
      description = element.at_xpath('Summary').content

      if !results[name]

        results[name] = {}
        results[name]["Hosts"] = Set.new
        results[name]["Description"] = description
        results[name]["Risk"] = risk.downcase

      end

      results[name]["Hosts"].add(host)

    end

    #binding.pry

    return results
  end


  # parse an individual acunetix file
  # take the data and put it into a format that we can match with the
  # other scanner output types
  def parse_acunetix_file(filename, results)

    #binding.pry
    doc = Nokogiri::XML(File.open(filename))
    #binding.pry

    report_items = doc.xpath('//ScanGroup/Scan/ReportItems/ReportItem')
    report_items.each do |element|

      #binding.pry
      host = doc.at_xpath('//StartURL').content
      name = element.at_xpath('Name').content
      risk = element.at_xpath('Severity').content
      description = element.at_xpath('Description').content

      if !results[name]

        results[name] = {}
        results[name]["Hosts"] = Set.new
        results[name]["Description"] = description
        results[name]["Risk"] = risk

      end

      results[name]["Hosts"].add(host)

    end

    #binding.pry

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
          results[row["Plugin ID"]]["Hosts"] = Set.new # use a set so we can remove duplicate host entries
          results[row["Plugin ID"]]["Description"] = row["Description"]
          results[row["Plugin ID"]]["Plugin Output"] = row["Plugin Output"]
          results[row["Plugin ID"]]["Risk"] = row["Risk"].downcase
          results[row["Plugin ID"]]["CVE"] = row["CVE"]
          results[row["Plugin ID"]]["CVSS"] = row["CVSS"]
        end

        results[row["Plugin ID"]]["Hosts"].add(row["Host"])
      end
    end

    return results
  end

end

JIRAUpdate.new.run_from_options(ARGV) if __FILE__ == $PROGRAM_NAME
