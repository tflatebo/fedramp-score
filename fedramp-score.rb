#!/usr/bin/env ruby
require 'optparse'
require 'json'
require 'csv'
require 'set'

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

    results = {}

    Dir.foreach(@options[:directory]) do |file|
      next if file == '.' or file == '..'

      results = parse_nessus_file(@options[:directory] + '/' + file, results)

    end

    output_score(results)
  end

  # print the score in a meaningful fashion
  def output_score(scan_data)

    score = {}

    scan_data.each do |scan_id, results|

      if !score[results["Risk"]]

        score[results["Risk"]] = {}

        score[results["Risk"]]["Findings"] = 0
        score[results["Risk"]]["Host Count"] = 0

      end


      score[results["Risk"]]["Findings"] += 1
      score[results["Risk"]]["Host Count"] += results["Hosts"].count

#      binding.pry
    end

    puts score.to_json

  end

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
          results[row["Plugin ID"]]["Risk"] = row["Risk"]
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
