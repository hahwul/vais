class OptparseVAIS
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    options = OpenStruct.new
    options.update = false

    opt_parser = OptionParser.new do |opts|
      opts.banner = 'Usage: vais.rb [swf file path][options]'

      opts.separator ''
      opts.separator 'Specific options:'

      opts.on('-u', '--update', 'update') do
        options.update = true
      end

      opts.separator ''
      opts.separator 'Common options:'

      # No argument, shows at tail.  This will print an options summary.
      # Try it and see!
      opts.on_tail('-h', '--help', 'Show this message') do
        puts opts
        exit
      end
      opts.on('-v', '--version', 'Print version') do
        print "V\n"
        exit
      end
    end
    opt_parser.parse!(args)
    options
  end # parse()
end
