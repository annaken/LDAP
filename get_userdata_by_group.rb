require 'rubygems'
require 'net/ldap'
require 'optparse'

$options = {}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: getpubkey.rb [$options]"

  opts.on('-n', '--authname authname', 'Username for authentication and querying LDAP') do |authname|
    $options[:authname] = authname
  end
  opts.on('-p', '--authpassword authpassword', 'Password for authentication and querying LDAP') do |authpassword|
    $options[:authpassword] = authpassword
  end
  opts.on('-s', '--adserver adserver', 'AD server') do |adserver|
    $options[:adserver] = adserver
  end
  opts.on('-g', '--usergroup usergroup', 'User group') do |usergroup|
    $options[:usergroup] = usergroup
  end
  opts.on('-d', '--outputdir outputdir', 'Output directory (optional)') do |outputdir|
    $options[:outputdir] = outputdir
  end
  opts.on('-v', '--verbose', 'Verbose output') do |verbose|
    $options[:verbose] = verbose
  end
end
parser.parse!


### Verbose output for debugging ###
def verbose_output (ldap, operation)
    print operation
    puts ldap.get_operation_result.message
end

### Convert AD server to ldap base ###
unless $options[:adserver].nil?
  adserver = $options[:adserver]
  searchbase = adserver.gsub(/^[a-zA-Z]+\./, "DC=").gsub(/\./, ",DC=")
else
  puts "Please specify an AD server"
  abort
end

unless $options[:usergroup].nil?
  groupfilter = Net::LDAP::Filter.eq("memberOf", "CN=#{$options[:usergroup]},OU=Groups,#{searchbase}")
else
  puts "Please specify a usergroup"
  abort
end

filter = Net::LDAP::Filter.construct("(&(objectClass=User)(memberOf=CN=#{$options[:usergroup]},OU=Groups,#{searchbase})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")


### Do LDAP bind with readonly user (NB this is NOT encrypted) ###
ldap = Net::LDAP.new :host => adserver, :port => 389, :auth => {
  :method => :simple,
  :username => $options[:authname],
  :password => $options[:authpassword]
}
$options[:verbose]? verbose_output(ldap, "Attempting LDAP bind: ") : "nil"


### Get the following attributes from AD  ###
### sam account name (login name)         ###
### street address                        ###
attrs = ["samaccountname", "streetaddress"]

unless $options[:outputdir] == nil
  filename = $options[:outputdir] + $options[:usergroup].downcase.gsub(/( )/, '_') + "_userdata.txt"
else
  filename = ($options[:usergroup].downcase.gsub(/( )/, '_') + "_userdata.txt")
end

output = File.open(filename, "w+")

ldap.search(:base => "CN=Users,#{searchbase}", :filter => filter, :attributes => attrs, :return_result => true) do |entry|

  output.print entry.samaccountname[0]
  output.print " : "

  if entry.respond_to? (:streetaddress)
    output.print entry.streetaddress[0]
  end

  output.print "\n"
end

### Do the actual query ###
$options[:verbose]? verbose_output(ldap, "Attempting LDAP query: ") : nil

output.close
