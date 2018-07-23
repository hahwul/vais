require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'
require 'time'

require File.dirname(__FILE__) + '/config/config.rb' # Include Config File
require File.dirname(__FILE__) + '/src/optparse.rb'  # Include OptParse
require File.dirname(__FILE__) + '/src/swfClass.rb'  # Include SWFClass

def banner
  puts ''
  puts 'code by hahwul [www.hahwul.com].'
end

def update
  puts 'VAIS> Updating new version'
  Dir.chdir(File.dirname(__FILE__))
  # system("git pull -v")
  puts 'VAIS> Updated successfully.'
end

options = OptparseVAIS.parse(ARGV)
# pp options
# pp ARGV

if ARGV.empty?
  banner
  puts 'VAIS> Plase [taget swf] file.'
end
if options.update == true
  update
else
  ARGV.each do |arg|
    object = SWFObject.new(arg)
    object.scan
  end
end
