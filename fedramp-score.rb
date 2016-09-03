#!/usr/bin/env ruby
require 'optparse'
require 'net/https'
require 'json'
require 'csv'

require 'pry'

class FedRAMPScore

  def initialize()
    @jira_host = ENV['JIRA_URI']
    @jira_port = 443
    @use_ssl = true
  end

  def run_from_options(argv)
    parse_options(argv)

    if @options[:attachments]
      get_attachments(@options)
    elsif @options[:input_file]
      update_issues(@options)
    elsif @options[:updated_field_value]
      update_issue(@options)
    elsif @options[:search_value]
      find_issue(@options)
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
    #{__FILE__} -s key -k JIRA-123

  Find JIRA issue by custom field and display
    #{__FILE__} -s '\"Legacy%20Row%20No\"' -k M1-048

  Find JIRA issue where legacy row no. contains 'MI-048' and update the 'CFACTS' field to '1234'
    #{__FILE__} -s '\"Legacy%20Row%20No\"' -k M1-048 -n 'customfield_12850' -v '1234'

  Find JIRA issue by key and retrieve attachments into directory_name
    #{__FILE__} -s key -k JIRA-123 -a directory_name

Options:
      USAGE
      opts.on('-k', '--search_value VALUE', 'Field value to search with') do |p|
        @options[:search_value] = p
      end
      opts.on('-s', '--search_field FIELD', 'Field name to search with') do |p|
        @options[:search_field] = p
      end
      opts.on('-n', '--update_field_name FIELD', 'Field name to update') do |p|
        @options[:updated_field_name] = p
      end
      opts.on('-v', '--value_to_update VALUE', 'Field value to update with') do |p|
        @options[:updated_field_value] = p
      end
      opts.on('-f', '--read_from_file FILENAME', 'Read inputs from a file') do |p|
        @options[:input_file] = p
      end
      opts.on('-a', '--attachments DIRNAME', 'Download attachments into DIRNAME') do |p|
        @options[:attachments] = p
      end
    end.parse!(argv)
  end

  # update multiple issues from a CSV file
  # values are in this order: search_field_name,search_field_value,update_field_name,update_field_value
  def update_issues(options)
    CSV.foreach(@options[:input_file]) do |row|
      #puts "find: " + row[0] + " " + row[1] + " update: " + row[2] + " " + row[3]
      update_issue_internal('"' + row[0] + '"', row[1], row[2], row[3])
    end
  end

  def update_issue(options)
    update_issue_internal(@options[:search_field], @options[:search_value], @options[:updated_field_name], @options[:updated_field_value])
  end

  # update a single issue with values from command line
  def update_issue_internal(search_field, search_value, updated_field_name, updated_field_value)
    search_results = search_jira(search_field, search_value)
    jira_issue = get_jira(search_results["issues"][0]["self"])

    puts "Updating " + jira_issue["key"] + ": " + updated_field_name + " from '" + jira_issue["fields"][updated_field_name].to_s + "' to '" + updated_field_value + "'"

    # blank out all of the fields so we don't try to update a bunch of crap, only what we want
    jira_issue["fields"] = {}
    jira_issue["fields"][updated_field_name] = updated_field_value

    if(update_jira(jira_issue))
      #puts "Success!"
    else
      puts "ERROR: see output"
    end
  end

  def find_issue(options)

    jira_issue = search_jira(@options[:search_field], @options[:search_value])

    puts "Self: #{jira_issue["issues"][0]["self"]}"
    puts "Key: #{jira_issue["issues"][0]["key"]}"
    puts "Row #: #{jira_issue["issues"][0]["fields"]["customfield_12775"]}"
    puts "CFACTS: #{jira_issue["issues"][0]["fields"]["customfield_12850"].to_s}"

    puts "Fields: #{jira_issue["issues"][0].keys}"

    if(jira_issue["issues"][0]["fields"]["attachment"])
      puts "Attachments: #{jira_issue["issues"][0]["fields"]["attachment"]}"
    end

    return jira_issue

  end

  # update an issue
  def update_jira(jira_issue)
    @jira_issue = ''

    #puts "Sending " + jira_issue.to_json

    uri = URI(jira_issue["self"])

    # first GET the issue:
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = @use_ssl
    http.start do |http|
      req = Net::HTTP::Put.new(uri.path, initheader = {'Content-Type' =>'application/json'})

      req.body = jira_issue.to_json

      # we make an HTTP basic auth by passing the
      # username and password
      req.basic_auth ENV['JIRA_USER'], ENV['JIRA_PASS']
      resp, data = http.request(req)
      #puts "Update resp: " + resp.code + "\n"

      if resp.code.eql? '204'
        return true
      else
        puts "Error: " + resp.code.to_s + "\n" + resp.body.to_s
      end
    end

    return @jira_issue
  end

  # get an issue, return it in a hash
  def get_jira(uri_in)
    @jira_issue = ''

    uri = URI(uri_in)

    # first GET the issue:
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = @use_ssl
    http.start do |http|
      req = Net::HTTP::Get.new(uri.path)

      # we make an HTTP basic auth by passing the
      # username and password
      req.basic_auth ENV['JIRA_USER'], ENV['JIRA_PASS']
      resp, data = http.request(req)
      #puts "Get resp: " + resp.code + "\n"

      if resp.code.eql? '200'
        #print "Data: " +  JSON.pretty_generate(JSON.parse(resp.body.to_s))
        @jira_issue = JSON.parse(resp.body.to_s)
      else
        puts "Error: " + resp.code.to_s + "\n" + resp.body
      end
    end

    return @jira_issue
  end

  # search for an issue, return search results
  def search_jira(field, issue_key)

    @jira_issue = ''

    if(field == 'key')
      operator = '='
    else
      operator = '~'
    end

    http = Net::HTTP.new(@jira_host, @jira_port)
    http.use_ssl = @use_ssl
    http.start do |http|
      req = Net::HTTP::Get.new('/rest/api/2/search?jql=' + field + operator + issue_key)

      # we make an HTTP basic auth by passing the
      # username and password
      req.basic_auth ENV['JIRA_USER'], ENV['JIRA_PASS']
      resp, data = http.request(req)
      #puts "Search resp: " + resp.code + "\n"

      if resp.code.eql? '200'
        #print "Data: " +  JSON.pretty_generate(JSON.parse(resp.body.to_s))
        @jira_issue = JSON.parse(resp.body.to_s)
      else
        puts "Error: " + resp.code.to_s + "\n" + resp.body
      end
    end

    return @jira_issue
  end

  def get_attachments(options)
    search_results = search_jira(@options[:search_field], @options[:search_value])
    jira_issue = get_jira(search_results["issues"][0]["self"])

    #puts "#{jira_issue['fields']['attachment'].to_json}"

    jira_issue['fields']['attachment'].each do |attachment|

      puts "#{attachment["filename"]}: #{attachment["content"]}"

      get_and_store_attachment(@options[:attachments], attachment["filename"], attachment["content"])

    end

  end

  def get_and_store_attachment(dir, filename, uri)

    f = File.open(dir + '/' + filename, 'w')

    begin

      uri = URI(uri)

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = @use_ssl
      http.start do |http|
        req = Net::HTTP::Get.new(uri.path)

        # we make an HTTP basic auth by passing the
        # username and password
        req.basic_auth ENV['JIRA_USER'], ENV['JIRA_PASS']
        http.request(req) do |resp|
          puts "Get resp: " + resp.code + "\n"

          if resp.code.eql? '200'
            #print "Data: " +  JSON.pretty_generate(JSON.parse(resp.body.to_s))
            resp.read_body do |segment|
              f.write(segment)
            end
          else
            puts "Error: " + resp.code.to_s + "\n" + resp.body
          end
        end
      end

    ensure
      f.close()
    end
  end


end

FedRAMPScore.new.run_from_options(ARGV) if __FILE__ == $PROGRAM_NAME
