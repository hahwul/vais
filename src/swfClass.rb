class SWFObject
	def initialize(fp)
		@time = Time.new
		@swf = fp
		@swf_workspace = Dir.pwd+"/"+@swf+"."+(@time.to_i).to_s
		@swf_report = ""
		
		@swf_dump = ""
		@swf_actionscript = Array.new()
		@swf_vuln = []  #  level | vulnerability | file | line | code data
		@swf_loaderInfo = []   # file | line | code data
		
		@swf_report_path=""
		@swf_report_templatet=File.dirname(__FILE__)+"/rtemplate_t.html"
		@swf_report_templateb=File.dirname(__FILE__)+"/rtemplate_b.html"
		@swf_report_data=""
	end
	def decompileSWF # Decompile SWF File [ flash > actionscript ] 
	# ffdec -export script ./asd simpleCalendar.swf
	puts " > Making source Directory"
	Dir.mkdir(@swf_workspace+"/source")
	puts " > Decompiling.."
	system($path_ffdec+" -export script "+@swf_workspace+"/source/ "+@swf+" > /dev/null 2>&1")  ## ffdec
	puts " > Success"
	end
	
	def dumpSWF # Dump SWF
	# swfdump -D	
	puts " > Dumping.."
	system($path_swfdump+" -D "+@swf+" > "+@swf_workspace+"/source/dump")  ## ffdec
	puts " > Success"
	end
	
	def findLoaderInfo
		#ActionScript2 
		#LoaderInfo(this.root.loaderInfo).parameters;
		#ActionScript3 
		#this.loaderInfo.parameters;
		i=0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("loaderInfo.parameters") != nil)
				sindex = @swf_actionscript[count].index("loaderInfo.parameters")
				@swf_loaderInfo.push([@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} input param point found!"
	end
	def findVulnFunction
		#loadVariables()
		#loadMovie()
		#getURL()
		#loadMovieNum()
		#FScrollPane.loadScrollContent()
		#LoadVars.load 
		#LoadVars.send 
		#XML.load ( 'url' )
		#LoadVars.load ( 'url' ) 
		#Sound.loadSound( 'url' , isStreaming ); 
		#NetStream.play( 'url' );
		i = 0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("loadVariables(") != nil)
				sindex = @swf_actionscript[count].index("loadVariables(")
				@swf_vuln.push(2,"vuln func - loadVariables()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("loadMovie(") != nil)
				sindex = @swf_actionscript[count].index("loadMovie(")
				@swf_vuln.push(2,"vuln func - loadMovie()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("getURL(") != nil)
				sindex = @swf_actionscript[count].index("getURL(")
				@swf_vuln.push(2,"vuln func - getURL()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("loadMovieNum(") != nil)
				sindex = @swf_actionscript[count].index("loadMovieNum(")
				@swf_vuln.push(2,"vuln func - loadMovieNum()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("FScrollPane.loadScrollContent(") != nil)
				sindex = @swf_actionscript[count].index("FScrollPane.loadScrollContent(")
				@swf_vuln.push(2,"vuln func - FScrollPane.loadScrollContent()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("LoadVars.load(") != nil)
				sindex = @swf_actionscript[count].index("LoadVars.load(")
				@swf_vuln.push(2,"vuln func - LoadVars.load()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("LoadVars.send(") != nil)
				sindex = @swf_actionscript[count].index("LoadVars.send(")
				@swf_vuln.push(2,"vuln func - LoadVars.send()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("XML.load(") != nil)
				sindex = @swf_actionscript[count].index("XML.load(")
				@swf_vuln.push(2,"vuln func - XML.load()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("Sound.loadSound(") != nil)
				sindex = @swf_actionscript[count].index("Sound.loadSound(")
				@swf_vuln.push(2,"vuln func - Sound.loadSound()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
			if(@swf_actionscript[count].index("NetStream.play(") != nil)
				sindex = @swf_actionscript[count].index("NetStream.play(")
				@swf_vuln.push(2,"vuln func - NetStream.play()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} vulnerable function point found!"
	end
	def findExternalInterface
		i=0
		for count in 0 ... @swf_actionscript.size
			if(@swf_actionscript[count].index("ExternalInterface.call(") != nil)
				sindex = @swf_actionscript[count].index("ExternalInterface.call(")
				@swf_vuln.push(3,"use ExternalInterface.call()",[@aslist[count],sindex,@swf_actionscript[count][sindex-20..sindex+500]])
				i=i+1
			end
		end
		puts "   - #{i} ExternalInterface.call() found!"
	end
	
	def vanalysis
		# @swf_workspace+"/source/script/" is actionscript directory
		# @swf_workspace+"/source/dump" is dump result
		fdump = File.open(@swf_workspace+"/source/dump","r")
		fdump.each_line do | line |
			@swf_dump =  @swf_dump+line
		end
		puts " > Loaded dump file"
		@aslist = Dir[@swf_workspace+'**/**/*.as']
		for index in 0 ... @aslist.size
			#puts "@aslist[#{index}] = #{@aslist[index].inspect}"
			fasTemp = ""
			fas = File.open(@aslist[index], "r")
				fas.each_line do | line |
					fasTemp = fasTemp+line
				end		
			@swf_actionscript.push(fasTemp)
		end
		puts " > Loaded all actionscript [#{@aslist.size}] files"
		findLoaderInfo()
		findVulnFunction()
		findExternalInterface

	end
	
	def genReport # Generate Report file
		@swf_report_path = "./report_"+@swf+"."+(@time.to_i).to_s+".html"
		#system("touch "+@swf_report)
	end
	
	def scan()
		puts "Start VAIS.. Scanning to "+@swf+" file."
		puts "[INF] Making Workspace ["+@swf_workspace+"]" 
		Dir.mkdir(@swf_workspace)
		puts "[INF] Decompile SWF >> Actionscript" 
		decompileSWF()
		puts "[INF] Dump SWF File.." 
		dumpSWF()
		puts "[INF] Vulnerability Analysis.." 
		vanalysis()
		puts "[INF] Generate Report.." 
		genReport()
		puts "Scan Finish. open this file ["+@swf_report+"]"
		
	end
end
