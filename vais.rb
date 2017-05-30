require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'

require File.dirname(__FILE__)+"/config/config.rb"  #Include Config File
require File.dirname(__FILE__)+"/src/optparse.rb"  #Include OptParse
require File.dirname(__FILE__)+"/src/swfClass.rb"  #Include SWFClass

options = OptparseVAIS.parse(ARGV)
pp options
#pp ARGV

if ARGV.length == 0
	puts "Plase [taget swf] file."
end
ARGV.each do | arg |
	object = SWFObject.new(arg)
	object.scan
end


